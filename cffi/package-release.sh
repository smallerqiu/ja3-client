#!/usr/bin/env bash
# Turn whatever is under build/ into the release archives this repo publishes.
#
#   ./package-release.sh [dist-dir] [version]        # default: dist/, git tag
#
# Each archive holds one library plus everything needed to prove it works:
#
#   ja3-client-1.2.5-linux-amd64/
#     libja3_client_amd64.so      the library, named exactly as bindings/ look it up
#     ja3_client_amd64.h          the cgo header, same spelling on every OS
#     ja3_client_amd64.lib        windows only: MSVC import library
#     README.md                   the ABI contract (cffi/README.md)
#     ja3_client.py, smoke.py     python binding + offline check:
#                                 `python3 smoke.py` proves the download is good
#
# CI runs this once per build job, so a packaging change is a one-line review
# instead of a diff inside a workflow YAML.
set -euo pipefail

CFFI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="${1:-dist}"
VERSION="${2:-$(git -C "$(dirname "$CFFI_DIR")" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
VERSION="${VERSION:-dev}"

mkdir -p "$DIST"
DIST_ABS="$(cd "$DIST" && pwd)"

PACKAGED=0

# An artifact whose file name lies is worse than a missing one: bindings pick the
# library by `<os>_<arch>` name, so an arm64 dylib shipped as ja3_client_amd64.dylib
# loads on the wrong machines and fails somewhere far from here.
verify_arch() {
  lib="$1"
  arch="$2"
  desc="$(file -b "$lib")"

  case "$arch" in
    amd64) pattern='x86-64|x86_64' ;;
    arm64) pattern='aarch64|arm64' ;;
    armv7) pattern='ARM' ;;
    386)   pattern='80386|i386' ;;
    *)
      echo "unknown arch '${arch}' in ${lib}" >&2
      return 1
      ;;
  esac

  want=64
  if [ "$arch" = "386" ] || [ "$arch" = "armv7" ]; then want=32; fi

  is=64
  case "$desc" in
    *'64-bit'* | *'PE32+'*) is=64 ;;
    *) is=32 ;;
  esac

  if ! printf '%s' "$desc" | grep -qE "$pattern"; then
    echo "${lib} is named ${arch} but file says: ${desc}" >&2
    return 1
  fi

  if [ "$want" != "$is" ]; then
    echo "${lib} is named ${arch} (${want}-bit) but file says: ${desc}" >&2
    return 1
  fi

  return 0
}

while IFS= read -r lib; do
  base="$(basename "$lib")"
  stem="${base%.*}"
  os="$(basename "$(dirname "$lib")")"
  arch="${stem##*ja3_client_}"
  slug="${os}-${arch}"

  verify_arch "$lib" "$arch"

  stage="$(mktemp -d)/ja3-client-${VERSION}-${slug}"
  mkdir -p "$stage"

  cp "$lib" "$stage/$base"

  # cgo writes the header beside the output, so linux has libja3_client_amd64.h
  # while windows/darwin have ja3_client_amd64.h. Ship one spelling.
  if [ -f "${lib%.*}.h" ]; then
    cp "${lib%.*}.h" "$stage/ja3_client_${arch}.h"
  fi

  if [ -f "${lib%.*}.lib" ]; then
    cp "${lib%.*}.lib" "$stage/"
  fi

  cp "$CFFI_DIR/README.md" "$stage/README.md"
  cp "$CFFI_DIR/bindings/python/smoke.py" "$CFFI_DIR/bindings/python/ja3_client.py" "$stage/"

  out="${DIST_ABS}/ja3-client-${VERSION}-${slug}.zip"
  rm -f "$out"
  (cd "$(dirname "$stage")" && zip -rq "$out" "$(basename "$stage")")
  echo "==> $(basename "$out") ($(du -h "$out" | cut -f1 | tr -d ' '))"

  rm -rf "$(dirname "$stage")"
  PACKAGED=$((PACKAGED + 1))
done < <(cd "$CFFI_DIR" && find build -type f \( -name '*.so' -o -name '*.dll' -o -name '*.dylib' \) | sort | sed "s|^|$CFFI_DIR/|")

if [ "$PACKAGED" = "0" ]; then
  echo "nothing to package under $CFFI_DIR/build - run 'make host' or ./build-docker.sh first" >&2
  exit 1
fi

echo "==> ${PACKAGED} archive(s) in ${DIST}"
