#!/usr/bin/env python3
"""CTI SpiderFoot bridge.

Runs a real SpiderFoot scan using the installed WSL SpiderFoot runtime,
then streams logs, results, and correlations as JSON lines to stdout so the
PHP worker can project them into CTI MySQL.
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import multiprocessing as mp
import os
import sqlite3
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

FINAL_STATUSES = {"ERROR-FAILED", "ABORT-REQUESTED", "ABORTED", "FINISHED"}


def emit(kind: str, **payload: Any) -> None:
    record = {"kind": kind}
    record.update(payload)
    print(json.dumps(record, ensure_ascii=False), flush=True)


def load_payload(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("Payload root must be an object")
    return payload


def normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on"}


def cast_value(value: Any, template: Any) -> Any:
    if isinstance(template, bool):
        return normalize_bool(value)
    if isinstance(template, int) and not isinstance(template, bool):
        try:
            return int(str(value).strip())
        except Exception:
            return template
    if isinstance(template, float):
        try:
            return float(str(value).strip())
        except Exception:
            return template
    if isinstance(template, list):
        if isinstance(value, list):
            return value
        text = str(value or "").strip()
        if not text:
            return []
        return [part.strip() for part in text.replace("\r", "\n").replace(",", "\n").split("\n") if part.strip()]
    return "" if value is None else str(value)


def build_default_config(helpers: Any) -> Dict[str, Any]:
    generic_users = ""
    if hasattr(helpers, "usernamesFromWordlists"):
        try:
            generic_users = ",".join(helpers.usernamesFromWordlists(["generic-usernames"]))
        except Exception:
            generic_users = ""

    return {
        "_debug": False,
        "_maxthreads": 3,
        "__logging": True,
        "__outputfilter": None,
        "_useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0",
        "_dnsserver": "",
        "_fetchtimeout": 15,
        "_internettlds": "https://publicsuffix.org/list/effective_tld_names.dat",
        "_internettlds_cache": 72,
        "_genericusers": generic_users or "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,registrar,registry,root,routing-registry,rr,sales,security,spam,support,sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www",
        "__database": "",
        "__modules__": None,
        "__correlationrules__": None,
        "_socks1type": "",
        "_socks2addr": "",
        "_socks3port": "",
        "_socks4user": "",
        "_socks5pwd": "",
    }


def apply_global_settings(config: Dict[str, Any], global_settings: Dict[str, Any]) -> None:
    config["_debug"] = normalize_bool(global_settings.get("debug", config["_debug"]))
    config["_maxthreads"] = max(1, int(global_settings.get("max_concurrent_modules", config["_maxthreads"]) or config["_maxthreads"]))
    config["_useragent"] = str(global_settings.get("user_agent", config["_useragent"]) or config["_useragent"])
    config["_dnsserver"] = str(global_settings.get("dns_resolver", config["_dnsserver"]) or "")
    config["_fetchtimeout"] = max(1, int(global_settings.get("http_timeout", config["_fetchtimeout"]) or config["_fetchtimeout"]))
    config["_internettlds"] = str(global_settings.get("tld_list_url", config["_internettlds"]) or config["_internettlds"])
    config["_internettlds_cache"] = max(1, int(global_settings.get("tld_cache_hours", config["_internettlds_cache"]) or config["_internettlds_cache"]))
    config["_genericusers"] = str(global_settings.get("generic_usernames", config["_genericusers"]) or config["_genericusers"])
    config["_socks1type"] = str(global_settings.get("socks_type", "") or "")
    config["_socks2addr"] = str(global_settings.get("socks_host", "") or "")
    config["_socks3port"] = str(global_settings.get("socks_port", "") or "")
    config["_socks4user"] = str(global_settings.get("socks_username", "") or "")
    config["_socks5pwd"] = str(global_settings.get("socks_password", "") or "")


def prepare_target(raw_target: str, helpers: Any) -> Tuple[str, str]:
    target = str(raw_target or "").strip()
    if not target:
        raise ValueError("Target is blank")

    target_input = target
    if " " in target_input and '"' not in target_input:
        target_input = f'"{target_input}"'
    if "." not in target_input and not target_input.startswith("+") and '"' not in target_input:
        target_input = f'"{target_input}"'

    target_type = helpers.targetTypeFromString(target_input)
    if not target_type:
        raise ValueError(f"SpiderFoot could not determine a supported target type for: {target}")

    return target_input.strip('"'), target_type


def open_sqlite(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_scan_status(conn: sqlite3.Connection, scan_guid: str) -> Optional[str]:
    row = conn.execute(
        "SELECT status FROM tbl_scan_instance WHERE guid = ? LIMIT 1",
        (scan_guid,),
    ).fetchone()
    if not row:
        return None
    return str(row[0])


def fetch_new_logs(conn: sqlite3.Connection, scan_guid: str, last_rowid: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT rowid, generated, component, type, message "
        "FROM tbl_scan_log "
        "WHERE scan_instance_id = ? AND rowid > ? "
        "ORDER BY rowid ASC",
        (scan_guid, last_rowid),
    ).fetchall()


def fetch_new_results(conn: sqlite3.Connection, scan_guid: str, last_rowid: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT c.rowid AS rowid, ROUND(c.generated) AS generated, c.data, "
        "       COALESCE(s.data, 'ROOT') AS source_data, c.module, c.type, "
        "       c.confidence, c.visibility, c.risk, c.hash, c.source_event_hash, "
        "       c.false_positive AS fp, t.event_descr, t.event_type "
        "FROM tbl_scan_results c "
        "LEFT JOIN tbl_scan_results s "
        "  ON s.scan_instance_id = c.scan_instance_id "
        " AND s.hash = c.source_event_hash "
        "LEFT JOIN tbl_event_types t ON t.event = c.type "
        "WHERE c.scan_instance_id = ? AND c.rowid > ? "
        "ORDER BY c.rowid ASC",
        (scan_guid, last_rowid),
    ).fetchall()


def fetch_correlations(conn: sqlite3.Connection, scan_guid: str) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT c.id, c.title, c.rule_id, c.rule_risk, c.rule_name, c.rule_descr, c.rule_logic, "
        "       GROUP_CONCAT(e.event_hash, ',') AS event_hashes "
        "FROM tbl_scan_correlation_results c "
        "LEFT JOIN tbl_scan_correlation_results_events e ON e.correlation_id = c.id "
        "WHERE c.scan_instance_id = ? "
        "GROUP BY c.id, c.title, c.rule_id, c.rule_risk, c.rule_name, c.rule_descr, c.rule_logic "
        "ORDER BY c.id ASC",
        (scan_guid,),
    ).fetchall()


def level_from_log_type(log_type: Any) -> str:
    text = str(log_type or "info").strip().lower()
    if text in {"error", "critical", "fatal"}:
        return "error"
    if text in {"warning", "warn"}:
        return "warning"
    if text == "debug":
        return "debug"
    return "info"


def bootstrap_spiderfoot(payload: Dict[str, Any]) -> Dict[str, Any]:
    sf_root = str(payload.get("spiderfoot_install_wsl") or os.environ.get("CTI_SPIDERFOOT_PATH") or "~/spiderfoot-4.0")
    sf_root = os.path.expanduser(sf_root)
    if not os.path.isdir(sf_root):
        raise RuntimeError(f"SpiderFoot install path not found: {sf_root}")

    if sf_root not in sys.path:
        sys.path.insert(0, sf_root)

    from sflib import SpiderFoot  # type: ignore
    from sfscan import startSpiderFootScanner  # type: ignore
    from spiderfoot import SpiderFootHelpers, SpiderFootDb, SpiderFootCorrelator  # type: ignore
    from spiderfoot.logger import logListenerSetup  # type: ignore

    return {
        "SpiderFoot": SpiderFoot,
        "startSpiderFootScanner": startSpiderFootScanner,
        "SpiderFootHelpers": SpiderFootHelpers,
        "SpiderFootDb": SpiderFootDb,
        "SpiderFootCorrelator": SpiderFootCorrelator,
        "logListenerSetup": logListenerSetup,
        "sf_root": sf_root,
    }


def load_modules_and_rules(
    sf_root: str,
    spiderfoot_cls: Any,
    helpers: Any,
    db_cls: Any,
    correlator_cls: Any,
    sf_config: Dict[str, Any],
) -> Tuple[Any, Dict[str, Any], Dict[str, str], Any]:
    sf = spiderfoot_cls(sf_config)
    my_path = sf_root
    if hasattr(sf, "myPath"):
        try:
            my_path = sf.myPath()
        except Exception:
            my_path = sf_root

    mod_dir = os.path.join(my_path, "modules")
    corr_dir = os.path.join(my_path, "correlations")

    if not os.path.isdir(mod_dir):
        raise RuntimeError(f"SpiderFoot modules directory not found: {mod_dir}")
    if not os.path.isdir(corr_dir):
        raise RuntimeError(f"SpiderFoot correlations directory not found: {corr_dir}")

    if hasattr(helpers, "loadModulesAsDict"):
        modules = helpers.loadModulesAsDict(mod_dir, ["sfp_template.py"])
    else:
        modules = {}
        for filename in sorted(os.listdir(mod_dir)):
            if not filename.endswith(".py") or not filename.startswith("sfp_") or filename == "sfp_template.py":
                continue
            mod_name = filename[:-3]
            mod = importlib.import_module(f"modules.{mod_name}")
            obj = getattr(mod, mod_name)()
            mod_dict = obj.asdict() if hasattr(obj, "asdict") else {}
            modules[mod_name] = {"object": obj}
            if isinstance(mod_dict, dict):
                modules[mod_name].update(mod_dict)

    if hasattr(helpers, "loadCorrelationRulesRaw"):
        correlation_rules_raw = helpers.loadCorrelationRulesRaw(corr_dir, ["template.yaml"])
    else:
        correlation_rules_raw = {}
        for filename in sorted(os.listdir(corr_dir)):
            if not filename.endswith(".yaml") or filename == "template.yaml":
                continue
            rule_name = filename[:-5]
            with open(os.path.join(corr_dir, filename), "r", encoding="utf-8") as handle:
                correlation_rules_raw[rule_name] = handle.read()

    try:
        dbh = db_cls(sf_config, init=True)
    except TypeError:
        dbh = db_cls(sf_config)

    return sf, modules, correlation_rules_raw, dbh


def configure_modules(payload: Dict[str, Any], sf_config: Dict[str, Any], modules: Dict[str, Any]) -> List[str]:
    selected_sfp = [str(item).strip() for item in (payload.get("selected_sfp_modules") or []) if str(item).strip()]
    cti_by_sfp = payload.get("cti_by_sfp") or {}
    module_settings = payload.get("module_settings") or {}
    api_configs = payload.get("api_configs_snapshot") or {}

    modlist: List[str] = []
    missing_modules: List[str] = []

    for sfp_name in selected_sfp:
        if sfp_name not in modules:
            missing_modules.append(sfp_name)
            continue

        cti_slug = str(cti_by_sfp.get(sfp_name, "") or "").strip().lower()
        opts = modules[sfp_name].get("opts", {})
        if not isinstance(opts, dict):
            opts = {}
            modules[sfp_name]["opts"] = opts

        selected_settings = module_settings.get(cti_slug, {}) if cti_slug else {}
        if isinstance(selected_settings, dict):
            for key, value in selected_settings.items():
                if key in opts:
                    opts[key] = cast_value(value, opts[key])
                else:
                    opts[key] = value

        api_snapshot = api_configs.get(cti_slug, {}) if cti_slug else {}
        if isinstance(api_snapshot, dict):
            api_key = str(api_snapshot.get("api_key", "") or "").strip()
            if api_key and ("api_key" not in opts or not str(opts.get("api_key", "") or "").strip()):
                opts["api_key"] = api_key

        modlist.append(sfp_name)

    if missing_modules:
        emit("log", level="warning", module="bridge", message="Skipping unavailable SpiderFoot module(s): " + ", ".join(sorted(missing_modules)))

    if not modlist:
        return []

    if "sfp__stor_db" not in modlist:
        modlist.append("sfp__stor_db")

    return modlist


def run_bridge(payload: Dict[str, Any]) -> int:
    boot = bootstrap_spiderfoot(payload)
    SpiderFoot = boot["SpiderFoot"]
    start_scanner = boot["startSpiderFootScanner"]
    SpiderFootHelpers = boot["SpiderFootHelpers"]
    SpiderFootDb = boot["SpiderFootDb"]
    SpiderFootCorrelator = boot["SpiderFootCorrelator"]
    log_listener_setup = boot["logListenerSetup"]
    sf_root = boot["sf_root"]

    runtime_db_path = str(payload.get("runtime_db_path_wsl") or "").strip()
    if not runtime_db_path:
        payload_path = str(payload.get("_payload_path") or "")
        payload_dir = os.path.dirname(payload_path) if payload_path else sf_root
        runtime_db_path = os.path.join(payload_dir, f"spiderfoot_scan_{payload.get('scan_id', 'scan')}.db")

    Path(runtime_db_path).parent.mkdir(parents=True, exist_ok=True)

    sf_config = build_default_config(SpiderFootHelpers)
    sf_config["__database"] = runtime_db_path
    apply_global_settings(sf_config, payload.get("global_settings") or {})

    logging_queue: mp.Queue[Any] = mp.Queue()
    log_listener_setup(logging_queue, sf_config)
    logging.getLogger(f"spiderfoot.{__name__}")

    sf, modules, correlation_rules_raw, dbh = load_modules_and_rules(
        sf_root,
        SpiderFoot,
        SpiderFootHelpers,
        SpiderFootDb,
        SpiderFootCorrelator,
        sf_config,
    )

    if not modules:
        raise RuntimeError("No SpiderFoot modules found in runtime install")

    sf_correlation_rules: List[Dict[str, Any]] = []
    if correlation_rules_raw:
        correlator = SpiderFootCorrelator(dbh, correlation_rules_raw)
        sf_correlation_rules = correlator.get_ruleset()

    sf_config["__modules__"] = modules
    sf_config["__correlationrules__"] = sf_correlation_rules

    target_value, target_type = prepare_target(str(payload.get("query_value") or ""), SpiderFootHelpers)
    modlist = configure_modules(payload, sf_config, modules)
    if not modlist:
        raise RuntimeError("No SpiderFoot modules remained after mapping/filtering")

    cfg = sf.configUnserialize(dbh.configGet(), sf_config)
    cfg["_debug"] = sf_config["_debug"]

    scan_name = str(payload.get("scan_name") or payload.get("query_value") or "CTI SpiderFoot Scan")
    scan_guid = f"cti-{payload.get('scan_id', 'scan')}"

    emit(
        "meta",
        scan_guid=scan_guid,
        runtime_db_path=runtime_db_path,
        target=target_value,
        target_type=target_type,
        modules=modlist,
    )

    process = mp.Process(
        target=start_scanner,
        args=(logging_queue, scan_name, scan_guid, target_value, target_type, modlist, cfg),
    )
    process.daemon = True
    process.start()

    dbh.close()

    poll_conn = open_sqlite(runtime_db_path)
    last_log_rowid = 0
    last_result_rowid = 0

    try:
        while True:
            for row in fetch_new_logs(poll_conn, scan_guid, last_log_rowid):
                last_log_rowid = max(last_log_rowid, int(row["rowid"]))
                emit(
                    "log",
                    level=level_from_log_type(row["type"]),
                    module=str(row["component"] or ""),
                    message=str(row["message"] or ""),
                    generated=int(row["generated"] or 0),
                )

            for row in fetch_new_results(poll_conn, scan_guid, last_result_rowid):
                last_result_rowid = max(last_result_rowid, int(row["rowid"]))
                emit(
                    "result",
                    rowid=int(row["rowid"]),
                    generated=int(row["generated"] or 0),
                    data=str(row["data"] or ""),
                    source_data=str(row["source_data"] or "ROOT"),
                    module=str(row["module"] or ""),
                    event_code=str(row["type"] or ""),
                    event_descr=str(row["event_descr"] or row["type"] or "Unknown"),
                    event_group=str(row["event_type"] or ""),
                    confidence=int(row["confidence"] or 0),
                    visibility=int(row["visibility"] or 0),
                    risk=int(row["risk"] or 0),
                    event_hash=str(row["hash"] or ""),
                    source_event_hash=str(row["source_event_hash"] or "ROOT"),
                    false_positive=bool(row["fp"]),
                )

            status = fetch_scan_status(poll_conn, scan_guid)
            if status in FINAL_STATUSES and not process.is_alive():
                break

            if not process.is_alive() and status is None:
                break

            time.sleep(1)

        for row in fetch_new_logs(poll_conn, scan_guid, last_log_rowid):
            last_log_rowid = max(last_log_rowid, int(row["rowid"]))
            emit(
                "log",
                level=level_from_log_type(row["type"]),
                module=str(row["component"] or ""),
                message=str(row["message"] or ""),
                generated=int(row["generated"] or 0),
            )

        for row in fetch_new_results(poll_conn, scan_guid, last_result_rowid):
            last_result_rowid = max(last_result_rowid, int(row["rowid"]))
            emit(
                "result",
                rowid=int(row["rowid"]),
                generated=int(row["generated"] or 0),
                data=str(row["data"] or ""),
                source_data=str(row["source_data"] or "ROOT"),
                module=str(row["module"] or ""),
                event_code=str(row["type"] or ""),
                event_descr=str(row["event_descr"] or row["type"] or "Unknown"),
                event_group=str(row["event_type"] or ""),
                confidence=int(row["confidence"] or 0),
                visibility=int(row["visibility"] or 0),
                risk=int(row["risk"] or 0),
                event_hash=str(row["hash"] or ""),
                source_event_hash=str(row["source_event_hash"] or "ROOT"),
                false_positive=bool(row["fp"]),
            )

        status = fetch_scan_status(poll_conn, scan_guid) or "ERROR-FAILED"
        for row in fetch_correlations(poll_conn, scan_guid):
            hashes = [item for item in str(row["event_hashes"] or "").split(",") if item]
            emit(
                "correlation",
                correlation_id=str(row["id"] or ""),
                title=str(row["title"] or ""),
                rule_id=str(row["rule_id"] or ""),
                risk=str(row["rule_risk"] or "info"),
                rule_name=str(row["rule_name"] or ""),
                detail=str(row["rule_descr"] or ""),
                logic=str(row["rule_logic"] or ""),
                event_hashes=hashes,
            )

        emit("summary", status=status, log_row_count=last_log_rowid, result_row_count=last_result_rowid)

        process.join(timeout=10)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)

        return 0 if status == "FINISHED" else 1
    finally:
        poll_conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="CTI SpiderFoot bridge")
    parser.add_argument("--payload-path", required=True, help="Path to payload JSON")
    args = parser.parse_args()

    try:
        payload = load_payload(args.payload_path)
        payload["_payload_path"] = args.payload_path
        return run_bridge(payload)
    except Exception as exc:
        emit("log", level="error", module="bridge", message=f"Bridge failed: {exc}")
        emit("summary", status="ERROR-FAILED", log_row_count=0, result_row_count=0)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
