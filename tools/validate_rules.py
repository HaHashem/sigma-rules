#!/usr/bin/env python3
"""Lightweight checks for every rule: required fields, unique ids, valid tags, valid level.
Exit code 1 on any problem. Needs only PyYAML."""
import glob, re, sys, uuid
import yaml

REQUIRED = ["title", "id", "status", "description", "author", "date", "tags", "logsource", "detection", "level"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
TAG = re.compile(r"^attack\.([a-z\-]+|t\d{4}(\.\d{3})?)$")

def main():
    errors, ids = [], {}
    files = sorted(glob.glob("rules/**/*.yml", recursive=True))
    if not files:
        print("no rules found"); return 1
    for f in files:
        try:
            r = yaml.safe_load(open(f))
        except yaml.YAMLError as e:
            errors.append(f"{f}: invalid YAML: {e}"); continue
        for k in REQUIRED:
            if k not in r: errors.append(f"{f}: missing '{k}'")
        try: uuid.UUID(str(r.get("id")))
        except ValueError: errors.append(f"{f}: id is not a UUID")
        if r.get("id") in ids: errors.append(f"{f}: duplicate id also in {ids[r['id']]}")
        ids[r.get("id")] = f
        if r.get("level") not in LEVELS: errors.append(f"{f}: bad level")
        if r.get("status") not in STATUS: errors.append(f"{f}: bad status")
        tags = r.get("tags") or []
        if not any(re.match(r"attack\.t\d{4}", t) for t in tags): errors.append(f"{f}: no ATT&CK technique tag")
        for t in tags:
            if not TAG.match(t): errors.append(f"{f}: odd tag {t}")
        d = r.get("detection") or {}
        if "condition" not in d: errors.append(f"{f}: no condition")
        if not r.get("falsepositives"): errors.append(f"{f}: no falsepositives")
    for e in errors: print("ERROR", e)
    print(f"{len(files)} rules checked, {len(errors)} problems")
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
