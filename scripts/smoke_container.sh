#!/usr/bin/env bash
# smoke_container.sh — prove a container image produces a real case.
#
# Building is not the thing worth testing: a container that compiles and then
# writes an empty case directory is worse than no container, because the case
# looks like evidence. This runs the image the way an examiner runs it --
# evidence read-only, case directory writable, as an unprivileged uid with no
# passwd entry -- and checks what landed.
#
#   scripts/smoke_container.sh ghcr.io/wrongbaud/omnitrace:v0.2.0 [expected-git-sha]
set -euo pipefail

IMAGE=${1:?usage: smoke_container.sh <image> [expected-git-sha]}
EXPECT_SHA=${2:-}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIXTURES="$ROOT/tests/fixtures/out"
IMG=gpt.img   # GPT -> FAT32 + squashfs-xz: a partition table and two readers
[ -f "$FIXTURES/$IMG" ] || { echo "no fixture $FIXTURES/$IMG; run tests/fixtures/build.sh" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CASE="$WORK/case"
mkdir -p "$CASE"

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

echo "== $IMAGE"
before=$(sha256sum "$FIXTURES/$IMG" | cut -d' ' -f1)

version=$(docker run --rm "$IMAGE" --version)
echo "  version: $version"
if [ -n "$EXPECT_SHA" ]; then
  case "$version" in
    *"$EXPECT_SHA"*) ok "version reports the commit it was built from" ;;
    *) fail "--version ($version) does not name the expected commit $EXPECT_SHA" ;;
  esac
fi

# The run an examiner makes: evidence read-only, case writable, own uid.
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$FIXTURES:/data:ro" -v "$CASE:/out" \
  "$IMAGE" analyze "/data/$IMG" --out /out/gpt --tar-filesystems >"$WORK/run.log" 2>&1 \
  || { sed -n '1,40p' "$WORK/run.log" >&2; fail "analyze exited non-zero"; }

C="$CASE/gpt"
[ -s "$C/INFO.yaml" ] || fail "no INFO.yaml"
ok "INFO.yaml written"

if [ -n "$EXPECT_SHA" ]; then
  grep -q "git_sha: .*$EXPECT_SHA" "$C/INFO.yaml" \
    || fail "INFO.yaml does not record git_sha $EXPECT_SHA: $(grep git_sha "$C/INFO.yaml" || true)"
  ok "case records the build commit"
fi

# Two partitions carved, two filesystems read, files on disk. Thresholds are
# deliberately low: this asks whether the pipeline ran, not whether it is
# correct -- ctest in the builder stage already answered that.
parts=$(find "$C/partitions" -name '*.bin' 2>/dev/null | wc -l)
[ "$parts" -ge 2 ] || fail "expected >=2 carved partitions, got $parts"
ok "$parts partitions carved"

fsnodes=$(find "$C/filesystems" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
[ "$fsnodes" -ge 2 ] || fail "expected >=2 filesystem nodes, got $fsnodes"
ok "$fsnodes filesystem nodes"

files=$(find "$C/filesystems" -path '*/files/*' -type f 2>/dev/null | wc -l)
[ "$files" -ge 10 ] || fail "expected >=10 extracted files, got $files"
ok "$files files extracted"

tars=$(find "$C/filesystems" -name files.tar -size +0 2>/dev/null | wc -l)
[ "$tars" -ge 2 ] || fail "--tar-filesystems wrote $tars non-empty archives, expected >=2"
ok "$tars handover archives"

[ -s "$C/report.html" ] && [ -s "$C/report.md" ] || fail "no report"
ok "report rendered"

# The uid mapping is the whole reason for -u: a case owned by root is one the
# examiner cannot read on the host.
owner=$(stat -c '%u:%g' "$C/INFO.yaml")
[ "$owner" = "$(id -u):$(id -g)" ] || fail "case owned by $owner, not $(id -u):$(id -g)"
ok "case owned by the invoking user"

# Evidence is evidence. The mount is read-only; assert nothing touched it.
after=$(sha256sum "$FIXTURES/$IMG" | cut -d' ' -f1)
[ "$before" = "$after" ] || fail "the evidence image changed during the run"
ok "evidence unchanged ($before)"

echo "SMOKE PASS"
