#!/bin/sh
# Fully offline, never writes to any router or production feed.
set -eu
cd "$(dirname "$0")/.."
printf '===== TESTS =====\n'
python3 -m unittest discover -s tests -v
printf '===== SYNTAX =====\n'
python3 -m compileall -q threatip
printf '===== FIXTURE BUILD =====\n'
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
python3 -m threatip.build --config samples/fixture-config.json --out "$test_dir"
python3 - "$test_dir" <<'PY'
import hashlib, json, pathlib, sys
p=pathlib.Path(sys.argv[1]); manifest=json.loads((p/'manifest.json').read_text())
content=(p/'ipv4.txt').read_bytes()
assert manifest['ipv4_count']==4
assert hashlib.sha256(content).hexdigest()==manifest['ipv4_sha256']
print('ACCEPTANCE PASS: fixture build + SHA-256; RouterOS untouched (see test count above)')
PY
