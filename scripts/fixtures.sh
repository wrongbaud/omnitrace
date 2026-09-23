#!/usr/bin/env bash
# Convenience front end for the synthetic fixture builder (tests/fixtures).
#
#   scripts/fixtures.sh build [--native] [--only NAME ...]   # (re)generate tests/fixtures/out
#   scripts/fixtures.sh check                                # build twice, fail unless byte-identical
#   scripts/fixtures.sh list                                 # what is in tests/fixtures/out
#   scripts/fixtures.sh verify                               # every image matches its expected.yaml sha256
#   scripts/fixtures.sh clean                                # remove tests/fixtures/out
#   scripts/fixtures.sh parity IMAGE [run.py options]        # run the parity harness on one image
#   scripts/fixtures.sh sweep IMAGE... [sweep.py options]    # run it over many and aggregate one number
#
# `build` and `check` forward every other argument to tests/fixtures/build.sh
# (see its header for --native, --only, --out). Docs: docs/TESTING.md.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixtures="$root/tests/fixtures"
out="${FIXTURES_OUT:-$fixtures/out}"

cmd="${1:-build}"
[ $# -gt 0 ] && shift

case "$cmd" in
  build)
    exec "$fixtures/build.sh" --out "$out" "$@"
    ;;
  check)
    exec "$fixtures/build.sh" --out "$out" --check "$@"
    ;;
  list)
    if [ ! -f "$out/index.yaml" ]; then
      echo "no fixtures in $out (run: scripts/fixtures.sh build)" >&2
      exit 1
    fi
    python3 - "$out/index.yaml" <<'EOF'
import sys, yaml
idx = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
print(f"{'name':<22} {'format':<9} {'size':>10}  sha256")
for f in idx["fixtures"]:
    print(f"{f['name']:<22} {f['format']:<9} {f['size']:>10}  {f['sha256']}")
for s in idx.get("skipped", []):
    print(f"skipped {s['name']}: {s['reason']}")
EOF
    ;;
  verify)
    python3 - "$out" <<'EOF'
import hashlib, sys, yaml
from pathlib import Path
out = Path(sys.argv[1]); bad = 0
for y in sorted(out.glob("*.expected.yaml")):
    doc = yaml.safe_load(open(y, encoding="utf-8"))
    img = out / doc["image"]["file"]
    if not img.exists():
        print(f"MISSING {img.name}"); bad += 1; continue
    h = hashlib.sha256(img.read_bytes()).hexdigest()
    ok = h == doc["image"]["sha256"] and img.stat().st_size == doc["image"]["size"]
    print(f"{'ok     ' if ok else 'CHANGED'} {img.name}")
    bad += not ok
sys.exit(1 if bad else 0)
EOF
    ;;
  clean)
    rm -rf "$out"
    echo "removed $out"
    ;;
  parity)
    exec python3 "$root/tests/parity/run.py" "$@"
    ;;
  sweep)
    exec python3 "$root/tests/parity/sweep.py" "$@"
    ;;
  -h|--help|help)
    sed -n '2,13p' "$0"
    ;;
  *)
    echo "unknown command: $cmd (build|check|list|verify|clean|parity|sweep)" >&2
    exit 2
    ;;
esac
