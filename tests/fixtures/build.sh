#!/usr/bin/env bash
# Build the synthetic fixture images + ground-truth YAML into tests/fixtures/out.
#
#   tests/fixtures/build.sh            # Docker (default): every image, reproducible toolchain
#   tests/fixtures/build.sh --native   # host tools; fixtures whose tool is missing are skipped
#   tests/fixtures/build.sh --only jffs2-history --only ext4
#   tests/fixtures/build.sh --check    # build twice and fail if any image is not byte-identical
#
# The Docker path runs tests/fixtures/generate.py inside the image described by
# tests/fixtures/Dockerfile as root, with ./out bind-mounted at /out, then
# hands ownership of the output back to the invoking user. The native path
# needs mksquashfs, mkfs.ext4 + debugfs, mkfs.vfat + mtools for the common
# images and mtd-utils / yaffs2utils for jffs2, ubifs and yaffs2.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${FIXTURES_OUT:-$here/out}"
image_tag="${FIXTURES_IMAGE:-omnitrace-fixtures}"
mode=docker
check=0
gen_args=()

while [ $# -gt 0 ]; do
  case "$1" in
    --native) mode=native ;;
    --docker) mode=docker ;;
    --check) check=1 ;;
    --out) out="$2"; shift ;;
    --only|-v|--verbose|--skip-missing) gen_args+=("$1"); [ "$1" = "--only" ] && { gen_args+=("$2"); shift; } ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$out"

run_native() {
  python3 "$here/generate.py" --out "$out" --skip-missing "${gen_args[@]}"
}

run_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found; use --native" >&2
    exit 1
  fi
  docker build -q -t "$image_tag" "$here" >/dev/null
  # -u is deliberately *not* passed: mkyaffs2 and chown need root inside the
  # container. Ownership of ./out is restored afterwards.
  docker run --rm -v "$out:/out" "$image_tag" --out /out "${gen_args[@]}"
  docker run --rm -v "$out:/out" --entrypoint chown "$image_tag" -R "$(id -u):$(id -g)" /out
}

build_once() {
  if [ "$mode" = native ]; then run_native; else run_docker; fi
}

build_once

if [ "$check" = 1 ]; then
  first="$(mktemp)"
  (cd "$out" && sha256sum -- *.img *.tar.gz | sort) > "$first"
  build_once
  second="$(mktemp)"
  (cd "$out" && sha256sum -- *.img *.tar.gz | sort) > "$second"
  if ! diff -u "$first" "$second"; then
    echo "fixtures are not reproducible (see diff above)" >&2
    exit 1
  fi
  echo "reproducibility check passed: $(wc -l < "$second") images byte-identical across two builds"
  rm -f "$first" "$second"
fi

echo "fixtures written to $out"
