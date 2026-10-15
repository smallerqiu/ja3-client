#!/usr/bin/env bash
# Cross-compile the shared library for every platform a release ships.
#
#   ./build-docker.sh [version]              # the Makefile's `make docker` calls this
#   ./build-docker.sh --list                 # the Docker target ids (darwin builds
#                                            #  on a Mac: `make darwin`)
#   ./build-docker.sh 1.2.5 --only linux/arm64
#
# Why Docker: cgo means each target needs the matching C cross-compiler, and
# installing mingw + musl + armhf + multilib locally is a job nobody repeats. Each
# target builds in a throwaway golang image instead.
#
# Things worth knowing before changing this file:
#   * The whole repository is mounted, not just cffi/. cffi/go.mod carries
#     `replace github.com/smallerqiu/ja3-client => ../`, so the build uses the
#     library sources from this checkout - which is the point: what you ship is
#     what you tested, instead of whatever tag the go.mod pinned.
#   * github.com/smallerqiu/utls is NOT replaced, so it comes from the module
#     proxy. A release build therefore exercises the same dependency graph a
#     consumer gets, and it fails loudly if that version is not published.
#   * Linux targets build against Debian's glibc (bookworm), which is older than
#     what an Ubuntu runner ships, so the .so loads on distros that predate CI.
#   * macOS is excluded on purpose: Apple's SDK licence forbids building a dylib
#     in a Linux container. Run `make darwin` on a Mac (CI uses macos runners).
#   * Output names are the contract the bindings in bindings/ search for; they must
#     match the Makefile exactly.
#
# `--only` exists for CI: the release workflow runs one target per job so a broken
# cross-compiler fails a single artifact instead of the whole matrix.
set -euo pipefail

CFFI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$CFFI_DIR")"

# Fields, separated by `|`:
#   id | goos | goarch | goarm | output-file | CC | apt-packages | extra-ldflags |
#   import-lib | nm
#
# Pipe-separated rather than whitespace-separated because a target can need more
# than one apt package and that field has to keep its spaces. extra-ldflags and
# import-lib are mutually exclusive (elf vs pe); "-" means neither. The import
# library path is completed inside the container because go runs the C linker from
# a temporary directory, so a relative path there cannot be opened.
#
# The packages and the nm tool are spelled out per target instead of derived from
# CC, because Debian's naming has two traps a derivation falls into: linux/amd64 has
# no cross compiler package at all (gcc-x86-64-linux-gnu is built only for
# arm64/i386/ppc64el, so asking for it on the amd64 runner dies on "Unable to locate
# package" and the flagship artifact never ships - the image's own gcc is the right
# tool there), and native binutils ships plain `nm`, not x86_64-linux-gnu-nm.
#
# binutils-* is listed beside its gcc-* even though the gcc pulls it in: this script
# is the release gate, and an explicit dependency is cheaper than a CI run spent
# discovering that a dependency moved.
#
# libc6-dev-<arch>-cross has to be named too, and that one is not redundant: Debian
# makes it a Recommends of the cross gcc, and this script installs with
# --no-install-recommends, so the toolchain arrives without the target's C headers.
# The build then dies in runtime/cgo with fatal error: bits/wordsize.h /
# bits/libc-header-start.h: No such file or directory - the cross gcc finds its own
# include dir but the target libc is missing, and it falls back to the host /usr/include
# (Release run #9: amd64 and both windows targets shipped, all three Linux cross
# targets failed this way). mingw needs nothing similar because
# gcc-mingw-w64-* depends on the libc headers outright.
TARGETS=(
  "linux/amd64|linux|amd64|-|libja3_client_amd64.so|x86_64-linux-gnu-gcc|-|-Wl,-soname,libja3_client_amd64.so|-|nm"
  "linux/arm64|linux|arm64|-|libja3_client_arm64.so|aarch64-linux-gnu-gcc|gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-dev-arm64-cross|-Wl,-soname,libja3_client_arm64.so|-|aarch64-linux-gnu-nm"
  "linux/arm/v7|linux|arm|7|libja3_client_armv7.so|arm-linux-gnueabihf-gcc|gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf libc6-dev-armhf-cross|-Wl,-soname,libja3_client_armv7.so|-|arm-linux-gnueabihf-nm"
  "linux/386|linux|386|-|libja3_client_386.so|i686-linux-gnu-gcc|gcc-i686-linux-gnu binutils-i686-linux-gnu libc6-dev-i386-cross|-Wl,-soname,libja3_client_386.so|-|i686-linux-gnu-nm"
  "windows/amd64|windows|amd64|-|ja3_client_amd64.dll|x86_64-w64-mingw32-gcc|gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64|-|ja3_client_amd64.lib|x86_64-w64-mingw32-nm"
  "windows/386|windows|386|-|ja3_client_386.dll|i686-w64-mingw32-gcc|gcc-mingw-w64-i686 binutils-mingw-w64-i686|-|ja3_client_386.lib|i686-w64-mingw32-nm"
)

VERSION=""
ONLY=()

while [ $# -gt 0 ]; do
  case "$1" in
    --list)
      for row in "${TARGETS[@]}"; do
        IFS='|' read -r ID _ <<EOF
$row
EOF
        echo "$ID"
      done
      exit 0
      ;;
    --only)
      shift
      while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do
        ONLY+=("$1")
        shift
      done
      ;;
    -h|--help)
      awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    -*)
      echo "unknown option: $1 (try --help)" >&2
      exit 2
      ;;
    *)
      VERSION="$1"
      shift
      ;;
  esac
done

VERSION="${VERSION:-$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
VERSION="${VERSION:-dev}"
BUILD_TIME="${BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

GO_VERSION="$(awk '/^go [0-9]+\./ { split($2, v, "."); print v[1]"."v[2]; exit }' "$REPO_ROOT/go.mod")"
IMAGE="golang:${GO_VERSION}-bookworm"

LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"

selected() {
  local want="$1" id

  if [ "${#ONLY[@]}" -eq 0 ]; then
    return 0
  fi

  for id in "${ONLY[@]}"; do
    if [ "$id" = "$want" ]; then
      return 0
    fi
  done

  return 1
}

BUILT=0

for row in "${TARGETS[@]}"; do
  IFS='|' read -r ID GOOS GOARCH GOARM OUTFILE CC PKGS XTLD IMPLIB NM <<EOF
$row
EOF

  selected "$ID" || continue

  OUTDIR="build/${GOOS}"
  GOARM_FLAG=""
  if [ "$GOARM" != "-" ]; then GOARM_FLAG="-e"; fi

  echo "==> ${ID} -> ${OUTDIR}/${OUTFILE}"

  # Pull once per target: the images are cached by CI, and a wrong go.mod version
  # should fail on the first target rather than six.
  docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"

  # GOFLAGS=-buildvcs=false: building a main package makes `go build` stamp the git
  # revision into the binary, and that git call fails with exit 128 inside the
  # container - /src belongs to whoever owns the checkout on the host while git runs
  # as root, so git reports a dubious ownership. Every docker target died on it
  # before compiling a line (Release run #8). The library's identity comes from
  # -X main.Version anyway; the alternative, git config --global safe.directory
  # /src, would stamp a revision taken from a tree CI does not own.
  docker run --rm \
    -v "${REPO_ROOT}":/src \
    -w /src/cffi \
    -e GOWORK=off \
    -e CGO_ENABLED=1 \
    -e GOFLAGS=-buildvcs=false \
    -e GOOS="${GOOS}" \
    -e GOARCH="${GOARCH}" \
    ${GOARM_FLAG:+-e GOARM=${GOARM}} \
    -e CC="${CC}" \
    -e LDFLAGS="${LDFLAGS}" \
    -e PKGS="${PKGS}" \
    -e OUTDIR="${OUTDIR}" \
    -e OUTFILE="${OUTFILE}" \
    -e XTLD="${XTLD}" \
    -e IMPLIB="${IMPLIB}" \
    -e NM="${NM}" \
    "${IMAGE}" \
    bash -euo pipefail -c '
      apt-get update -qq

      # Unquoted on purpose: PKGS can name several packages, and quoting it here
      # would hand apt one argument called "gcc-aarch64-linux-gnu binutils-...".
      # "-" means the image already ships the toolchain (linux/amd64 builds with
      # its own gcc), which is not the same as installing a package that has no
      # build for this architecture.
      if [ "${PKGS}" != "-" ]; then
        apt-get install -y -qq --no-install-recommends ${PKGS} ca-certificates
      fi

      mkdir -p "${OUTDIR}"

      EXT=""
      if [ "${XTLD}" != "-" ]; then EXT="${XTLD}"; fi

      if [ "${IMPLIB}" != "-" ]; then
        IMPLIB_FLAGS="-Wl,--out-implib,$(pwd)/${OUTDIR}/${IMPLIB}"

        if [ -z "${EXT}" ]; then
          EXT="${IMPLIB_FLAGS}"
        else
          EXT="${EXT} ${IMPLIB_FLAGS}"
        fi
      fi

      if [ -z "${EXT}" ]; then
        go build -buildmode=c-shared -ldflags="${LDFLAGS}" -o "${OUTDIR}/${OUTFILE}" .
      else
        go build -buildmode=c-shared -ldflags="${LDFLAGS} -extldflags=${EXT}" \
          -o "${OUTDIR}/${OUTFILE}" .
      fi

      # Fail here rather than in a users ld: a buildmode mistake, a missing //export
      # or a renamed entry point all produce a library that loads and answers nothing.
      # PE keeps exports in the import library, and mingw nm cannot read them off the
      # dll, so the .lib is what gets checked there.
      if [ "${IMPLIB}" != "-" ]; then
        CHECK="${OUTDIR}/${IMPLIB}"
        SET=""
      else
        CHECK="${OUTDIR}/${OUTFILE}"
        SET="-D --defined-only"
      fi

      # The `|| true` is not slack: with pipefail, a library that exports nothing
      # makes grep fail, which aborts the assignment before FOUND ever gets set, and
      # the build dies with no count and no message - the one thing this check is for.
      FOUND=$("$NM" ${SET} "$CHECK" |
        grep -oE "ja3_(version|request|session_new|session_request|session_close|free)" |
        sort -u | wc -l | tr -d " " || true)

      if [ "${FOUND}" != "6" ]; then
        echo "only ${FOUND:-0} of 6 ABI exports in ${CHECK}" >&2
        "$NM" ${SET} "$CHECK" 2>&1 | head -20 >&2
        exit 1
      fi

      echo "    exports verified: ${FOUND}/6"
    '

  BUILT=$((BUILT + 1))
done

if [ "${#ONLY[@]}" -gt 0 ] && [ "$BUILT" = "0" ]; then
  echo "no target matched ${ONLY[*]} - see --list" >&2
  exit 2
fi

# The dylibs are the host build when this runs on a Mac, so `make docker` on a
# laptop still produces the whole set.
if [ "$(uname -s)" = "Darwin" ] && { [ ${#ONLY[@]} -eq 0 ] || printf '%s\n' "${ONLY[@]}" | grep -q '^darwin'; }; then
  echo "==> host is macOS: building both dylibs natively"
  (cd "$CFFI_DIR" && make darwin-amd64 darwin-arm64)
elif [ "$(uname -s)" != "Darwin" ] && { [ ${#ONLY[@]} -eq 0 ] || printf '%s\n' "${ONLY[@]}" | grep -q '^darwin'; }; then
  echo "==> host is not macOS: dylibs must be built on a Mac (CI: macos runner)"
fi

echo
echo "==> version=${VERSION} build_time=${BUILD_TIME} image=${IMAGE}"
echo "==> artifacts:"
find "${CFFI_DIR}/build" -type f \( -name '*.so' -o -name '*.dll' -o -name '*.dylib' -o -name '*.h' -o -name '*.lib' \) | sort
