from pathlib import Path
import re, uuid, yaml, sys
required={"title","id","status","description","references","author","date","tags","logsource","detection","falsepositives","level"}
errors=[]
for path in Path("rules").rglob("*.yml"):
    try:
        data=yaml.safe_load(path.read_text())
    except Exception as exc:
        errors.append(f"{path}: YAML error: {exc}"); continue
    missing=required-set(data or {})
    if missing: errors.append(f"{path}: missing {sorted(missing)}")
    try:
        if uuid.UUID(str(data.get("id"))).version != 4: errors.append(f"{path}: id is not UUIDv4")
    except Exception: errors.append(f"{path}: invalid UUID")
    tags=data.get("tags",[])
    if not any(str(t).startswith("attack.t") for t in tags): errors.append(f"{path}: missing ATT&CK technique tag")
    det=data.get("detection",{})
    if "condition" not in det: errors.append(f"{path}: detection has no condition")
if errors:
    print("\n".join(errors)); sys.exit(1)
print(f"Validated {len(list(Path('rules').rglob('*.yml')))} rules")
