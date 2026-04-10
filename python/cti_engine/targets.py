"""Target parsing and normalization."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re


DOMAIN_RX = re.compile(r"^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$", re.I)
EMAIL_RX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.I)
URL_RX = re.compile(r"^https?://", re.I)
PHONE_RX = re.compile(r"^\+[0-9]{6,}$")
BITCOIN_RX = re.compile(r"^(bc1[a-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,35})$")
CVE_RX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
HEX_HASH_RX = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


@dataclass(slots=True)
class NormalizedTarget:
    raw: str
    normalized: str
    target_type: str

    def to_dict(self) -> dict[str, str]:
        return {
            "raw": self.raw,
            "normalized": self.normalized,
            "target_type": self.target_type,
        }


def normalize_target(raw: str, explicit_type: str | None = None) -> NormalizedTarget:
    value = str(raw or "").strip()
    if not value:
        raise ValueError("Target cannot be blank")

    if explicit_type:
        target_type = str(explicit_type).strip().lower()
        if not target_type:
            raise ValueError("Explicit target type cannot be blank")
        return NormalizedTarget(raw=value, normalized=value, target_type=target_type)

    if URL_RX.match(value):
        return NormalizedTarget(raw=value, normalized=value, target_type="url")

    if EMAIL_RX.match(value):
        return NormalizedTarget(raw=value, normalized=value.lower(), target_type="email")

    if PHONE_RX.match(value):
        return NormalizedTarget(raw=value, normalized=value, target_type="phone")

    if BITCOIN_RX.match(value):
        return NormalizedTarget(raw=value, normalized=value, target_type="bitcoin")

    if CVE_RX.match(value):
        return NormalizedTarget(raw=value, normalized=value.upper(), target_type="cve")

    if HEX_HASH_RX.match(value):
        return NormalizedTarget(raw=value, normalized=value.lower(), target_type="hash")

    try:
        parsed = ipaddress.ip_address(value)
        return NormalizedTarget(raw=value, normalized=str(parsed), target_type="ip")
    except ValueError:
        pass

    if DOMAIN_RX.match(value):
        return NormalizedTarget(raw=value, normalized=value.lower(), target_type="domain")

    return NormalizedTarget(raw=value, normalized=value, target_type="username")

