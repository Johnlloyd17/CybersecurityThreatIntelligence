import ast
import json
import re
from pathlib import Path

root = Path.cwd()
modules_dir = root / 'spiderfoot-master' / 'modules'
data = json.loads((root / 'runtime' / 'tmp_maps.json').read_text(encoding='utf-8-sig'))
implemented_cti = set(data['cti_to_service'].keys())
implemented_service = set(data['cti_to_service'].values())
module_map = data['spiderfoot_module_map']

skip = {'sfp__stor_db', 'sfp__stor_stdout', 'sfp_template'}
key_re = re.compile(r'(api.*key|apikey|api_?token|access_?token|api.*secret|client_?secret|password|passwd|consumer_?secret|secret)', re.I)

def literal_assignments(tree):
    meta = None
    opts = None
    cls_name = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name.startswith('sfp_'):
            cls_name = node.name
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id in {'meta','opts'}:
                            try:
                                val = ast.literal_eval(stmt.value)
                            except Exception:
                                val = None
                            if target.id == 'meta':
                                meta = val
                            elif target.id == 'opts':
                                opts = val
    return cls_name, meta, opts

def module_info(path):
    text = path.read_text(encoding='utf-8', errors='replace')
    try:
        tree = ast.parse(text)
        cls_name, meta, opts = literal_assignments(tree)
    except SyntaxError:
        cls_name, meta, opts = None, None, None
    meta = meta if isinstance(meta, dict) else {}
    opts = opts if isinstance(opts, dict) else {}
    flags = [str(x).lower() for x in meta.get('flags', [])] if isinstance(meta.get('flags', []), list) else []
    name = str(meta.get('name') or path.stem)
    key_opts = [str(k) for k in opts.keys() if key_re.search(str(k))]
    opt_text_keys = []
    needs_key = 'apikey' in flags or bool(key_opts)
    # Some modules store API descriptions in optdescs with non-obvious option keys. Fallback text check, conservative.
    if not needs_key and re.search(r"['\"]flags['\"]\s*:\s*\[[^\]]*apikey", text, re.I):
        needs_key = True
    return {
        'sfp': path.stem,
        'file': path.name,
        'name': name,
        'flags': ','.join(flags),
        'key_opts': ','.join(key_opts),
        'needs_key': needs_key,
    }

rows = []
unmapped = []
for path in sorted(modules_dir.glob('sfp_*.py')):
    sfp = path.stem
    if sfp in skip:
        continue
    info = module_info(path)
    cti_slug = module_map.get(sfp)
    info['cti_slug'] = cti_slug or ''
    # Implemented if mapped CTI slug is in UI implemented keys, or mapped service slug is in service values.
    implemented = False
    if cti_slug:
        implemented = cti_slug in implemented_cti or cti_slug in implemented_service
    else:
        # Last-ditch direct conversion from sfp_foo to foo only to avoid false missing for identical service slugs.
        simple = sfp[4:].replace('_', '-')
        implemented = simple in implemented_cti or simple in implemented_service
    info['implemented'] = implemented
    if not implemented:
        rows.append(info)
    if not cti_slug:
        unmapped.append(info)

needs = sorted([r for r in rows if r['needs_key']], key=lambda r: (r['name'].lower(), r['sfp']))
nokey = sorted([r for r in rows if not r['needs_key']], key=lambda r: (r['name'].lower(), r['sfp']))

def print_table(title, data_rows):
    print(f"\n## {title} ({len(data_rows)})")
    print('| Module Name | SpiderFoot File | Suggested CTI Slug | Key indicator |')
    print('|---|---|---|---|')
    for r in data_rows:
        key_indicator = r['key_opts'] or (('flags=' + r['flags']) if r['flags'] else '-')
        print(f"| {r['name']} | `{r['file']}` | `{r['cti_slug'] or '(not mapped yet)'}` | {key_indicator} |")

print(f"total_spiderfoot_modules={len(list(modules_dir.glob('sfp_*.py')))-len(skip)}")
print(f"implemented_ui_modules={len(implemented_cti)}")
print(f"not_implemented_total={len(rows)}")
print(f"not_implemented_needs_key={len(needs)}")
print(f"not_implemented_no_key_or_unclear={len(nokey)}")
print_table('Not implemented and likely API-key required', needs)
print_table('Not implemented and no API key obvious from SpiderFoot metadata', nokey)
