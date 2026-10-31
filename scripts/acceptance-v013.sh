#!/bin/sh
# Fully offline and read-only; does not access RouterOS or third-party networks.
set -eu
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -q
python3 -m compileall -q threatip
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
python3 -m threatip.build --config samples/fixture-config.json --out "$root/old"
python3 -m threatip.build --config samples/fixture-config.json --out "$root/candidate"
python3 -m threatip.quality --old "$root/old/ipv4.txt" --candidate "$root/candidate/ipv4.txt" --policy config/quality-policy.json --out "$root/quality.json"
python3 - "$root" <<'PY'
from pathlib import Path
import json, sys
root=Path(sys.argv[1]); data=json.loads((root/'quality.json').read_text())
assert data['decision']=='PASS'
assert data['changes']['ipv4_addresses_added_to_coverage']==0
assert (root/'old/ipv4.txt').exists() and (root/'candidate/ipv4.txt').exists()
print('v0.1.3 OFFLINE ACCEPTANCE PASS; no public feed or router changed')
PY
