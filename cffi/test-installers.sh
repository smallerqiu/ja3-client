#!/bin/sh
# End-to-end test of the three installers against a fake GitHub Release.
#
# Everything runs offline-by-construction: the "release" is a directory served over HTTP
# on 127.0.0.1, so the download, the checksum, the extraction, the shared cache and every
# failure message get exercised with real bytes - and the test still passes on a machine
# with no route to the internet, which is exactly when those messages matter.
#
#   ./test-installers.sh          # every binding whose toolchain is installed
#   ./test-installers.sh -v       # also show each step's captured output
#
# A missing toolchain skips that binding instead of failing the run, because this has to
# be callable from `make check` on a machine that only installed one language. The
# contract checks that need no toolchain at all - the three package versions agreeing, the
# sums file covering every archive - run regardless.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERBOSE=0
if [ "${1:-}" = "-v" ]; then VERBOSE=1; fi

# Canonicalize: $TMPDIR on macOS ends in a slash, so mktemp's answer carries a `//` that
# the installers' own resolved paths do not - and an assertion that greps for a path then
# misses its own file.
WORK=$(CDPATH= cd -- "$(mktemp -d "${TMPDIR:-/tmp}/ja3-installers.XXXXXX")" && pwd -P)
FAILURES=""
RAN=0

cleanup() {
  for pid in $(cat "$WORK/pids" 2>/dev/null || true); do
    kill "$pid" 2>/dev/null || true
  done

  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

say()  { printf '%s\n' "$*" >&2; }
step() { printf '\n\033[36m==> %s\033[0m\n' "$*" >&2; }
log()  { [ "$VERBOSE" = 1 ] && sed 's/^/      /' "$1" >&2; return 0; }

fail() {
  FAILURES="$FAILURES
  - $*"
  say "FAIL $*"
}

ok() { say "ok   $*"; }

# --- assertions ------------------------------------------------------------

# expect_contains <label> <needle> <file>
expect_contains() {
  if grep -q -- "$2" "$3" 2>/dev/null; then ok "$1"; else
    fail "$1: expected to find '$2' in:
$(sed 's/^/      /' "$3")"
  fi
}

# expect_absent <label> <needle> <file>
expect_absent() {
  if grep -q -- "$2" "$3" 2>/dev/null; then
    fail "$1: did not expect '$2' in:
$(sed 's/^/      /' "$3")"
  else ok "$1"; fi
}

# expect_file <label> <path>
expect_file() {
  if [ -s "$2" ]; then ok "$1 ($(wc -c < "$2" | tr -d ' ') bytes)"; else
    fail "$1: $2 is missing or empty"
  fi
}

expect_empty_dir() {  # expect_empty_dir <label> <dir>
  if [ -z "$(ls -A "$2" 2>/dev/null)" ]; then ok "$1"; else fail "$1: $2 is not empty"; fi
}

# The three lines PACKAGING.md promises when a fetch is impossible.
assert_contract_message() {  # assert_contract_message <label> <file>
  expect_contains "$1 names the failure" "could not fetch the native library" "$2"
  expect_contains "$1 gives the URL" "tried: http://127.0.0.1:" "$2"
  expect_contains "$1 gives the recipe" "JA3_CLIENT_LIB=/path/to/lib" "$2"
}

# --- the version under test ------------------------------------------------
# The Makefile's VERSION comes from `git describe`, which is the last *published* tag and
# so lags a release that has not been tagged yet. The installers ask for the version they
# ship in, so the fake release has to be named after that, not after the tag.

VERSION=$(sed -n 's/^  "version": "\(.*\)",$/\1/p' "$ROOT/bindings/node/package.json" | head -1)
[ -n "$VERSION" ] || { say "could not read a version from bindings/node/package.json"; exit 1; }
TAG="v$VERSION"

step "Package versions agree on $VERSION"
PY_VERSION=$(sed -n 's/^PACKAGE_VERSION = "\(.*\)"/\1/p' "$ROOT/bindings/python/ja3_client_binaries.py")
CS_VERSION=$(sed -n 's| *<Version>\(.*\)</Version>|\1|p' "$ROOT/bindings/csharp/Ja3Client.csproj")
[ "$PY_VERSION" = "$VERSION" ] && ok "python $PY_VERSION" || fail "python says $PY_VERSION, node says $VERSION"
[ "$CS_VERSION" = "$VERSION" ] && ok "csharp $CS_VERSION" || fail "csharp says $CS_VERSION, node says $VERSION"

# The ABI number is written down in five places, and four of them are what a user
# installs. If they disagree, a binding rejects a library it should accept - or worse,
# accepts one it should not.
step "The ABI number agrees everywhere it is written"
abi_main=$(sed -n 's/^const ABIVersion = \(.*\)$/\1/p' "$ROOT/main.go")
abi_node=$(sed -n 's/^const ABI_VERSION = \(.*\);/\1/p' "$ROOT/bindings/node/index.js")
abi_py=$(sed -n 's/^ABI_VERSION = \(.*\)$/\1/p' "$ROOT/bindings/python/ja3_client.py")
abi_bin=$(sed -n 's/^ABI_VERSION = \(.*\)$/\1/p' "$ROOT/bindings/python/ja3_client_binaries.py")
abi_cs=$(sed -n 's|.*<_Ja3Abi[^>]*>\([^<]*\)</_Ja3Abi>.*|\1|p' "$ROOT/bindings/csharp/build/ja3-client.targets" | head -1)

for pair in "main.go=$abi_main" "node=$abi_node" "python=$abi_py" "python_binaries=$abi_bin" "csharp_targets=$abi_cs"; do
  [ "${pair#*=}" = "$abi_main" ] && ok "$pair" || fail "$pair disagrees with main.go ($abi_main)"
done

# --- this machine's slug ---------------------------------------------------

case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)  HOST_SLUG=darwin-arm64 ;;
  Darwin/x86_64) HOST_SLUG=darwin-amd64 ;;
  Linux/x86_64)  HOST_SLUG=linux-amd64 ;;
  Linux/aarch64) HOST_SLUG=linux-arm64 ;;
  Linux/armv7*)  HOST_SLUG=linux-armv7 ;;
  Linux/i?86)    HOST_SLUG=linux-386 ;;
  *) say "unsupported host $(uname -s)/$(uname -m)"; exit 1 ;;
esac
HOST_ARCH=${HOST_SLUG#*-}
HOST_OS=${HOST_SLUG%-*}

case "$HOST_OS" in
  # The file names are the release contract (PACKAGING.md): darwin and windows have
  # no `lib` prefix, linux does. Getting this wrong makes every "is it installed"
  # check below lie in the other direction.
  darwin)  LIB_NAME="ja3_client_$HOST_ARCH.dylib" ;;
  linux)   LIB_NAME="libja3_client_$HOST_ARCH.so" ;;
  windows) LIB_NAME="ja3_client_$HOST_ARCH.dll" ;;
esac

ASSET="ja3-client-$VERSION-$HOST_SLUG.zip"
say "host slug $HOST_SLUG, library $LIB_NAME"

# --- the fake release ------------------------------------------------------

step "Building the host library and packaging $TAG"
# `go` not on PATH turns HOST_OS/HOST_ARCH in the Makefile into empty strings, and the
# guard there now says so instead of recursing. The installers need a real build, so find
# the toolchain the way a shell that never sourced .zshrc would not - same fallback the
# dotnet lookup below uses.
if ! command -v go >/dev/null 2>&1; then
  for candidate in /usr/local/go/bin /opt/homebrew/bin /usr/lib/go/bin "$HOME/go/bin"; do
    if [ -x "$candidate/go" ]; then
      PATH="$candidate:$PATH"
      export PATH
      break
    fi
  done
fi
command -v go >/dev/null 2>&1 || {
  say "go is not on PATH - this harness builds the host library with 'make host'"
  exit 1
}

if ! make -C "$ROOT" host >"$WORK/host.log" 2>&1; then
  tail -20 "$WORK/host.log" >&2
  fail "make host"
  exit 1
fi

"$ROOT/package-release.sh" "$WORK/dist" "$VERSION" >"$WORK/package.log" 2>&1 || {
  cat "$WORK/package.log" >&2
  fail "package-release.sh"
  exit 1
}

RELEASE="$WORK/release"
mkdir -p "$RELEASE/$TAG"
cp "$WORK"/dist/*.zip "$WORK/dist/SHA256SUMS.txt" "$RELEASE/$TAG/"
[ -f "$RELEASE/$TAG/$ASSET" ] || { say "no $ASSET in the packaged release"; exit 1; }

expect_contains "the sums file covers this archive" " $ASSET\$" "$RELEASE/$TAG/SHA256SUMS.txt"

# Tampered: the archive's bytes change, the sums file does not.
cp -R "$RELEASE" "$WORK/release-bad"
python3 - "$WORK/release-bad/$TAG/$ASSET" <<'PY'
import sys
with open(sys.argv[1], 'r+b') as fh:
    fh.seek(1000)
    fh.write(bytes([fh.read(1)[0] ^ 0xFF]))
PY

# No sums file: an old release, or a mirror that only carries archives.
mkdir -p "$WORK/release-nosums/$TAG"
cp "$RELEASE/$TAG/$ASSET" "$WORK/release-nosums/$TAG/"

# Sums but no archive: a half-deleted release, or a version typo in the package.
mkdir -p "$WORK/release-noasset/$TAG"
cp "$RELEASE/$TAG/SHA256SUMS.txt" "$WORK/release-noasset/$TAG/"

step "Serving the fake releases"
serve() {  # serve <port> <directory> [file-that-must-exist]
  # --directory instead of `cd && python3`: a subshell means $! is the shell's pid, so
  # the cleanup trap would kill the wrapper and leave the server holding the port for
  # the next run - which then reads 404s out of a deleted directory.
  if lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; then
    say "port $1 is already in use: $(lsof -nP -iTCP:"$1" -sTCP:LISTEN | tail -1)"
    say "a server left over from an earlier run would answer with 404s from a deleted tree"
    exit 1
  fi

  python3 -m http.server "$1" --bind 127.0.0.1 --directory "$2" >"$WORK/server-$1.log" 2>&1 &
  echo $! >> "$WORK/pids"

  # The readiness probe can only ask for something this site really has: the no-sums
  # site is defined by its missing SHA256SUMS.txt, so probing for that file would wait
  # forever. The directory listing exists on every site; ${3:-} pins the good one.
  probe="http://127.0.0.1:$1/$TAG${3:+/$3}"
  i=0

  until curl -fsS -o /dev/null "$probe" 2>/dev/null; do
    i=$((i + 1))

    if [ "$i" -gt 100 ]; then
      say "server on :$1 never served $probe"
      cat "$WORK/server-$1.log" >&2
      exit 1
    fi
    sleep 0.1
  done
}
serve 8741 "$RELEASE" SHA256SUMS.txt
serve 8742 "$WORK/release-bad" SHA256SUMS.txt
serve 8743 "$WORK/release-nosums"
serve 8744 "$WORK/release-noasset" SHA256SUMS.txt

BASE_GOOD=http://127.0.0.1:8741
BASE_BAD=http://127.0.0.1:8742
BASE_NOSUMS=http://127.0.0.1:8743
BASE_NOASSET=http://127.0.0.1:8744

# How many times a server was asked for the archive - the reuse checks read this.
downloads() { grep -c "GET /$TAG/$ASSET" "$WORK/server-$1.log" 2>/dev/null || true; }

CACHE_N=0
# Called as `cache=$(fresh_cache)`, which is a subshell - so the counter cannot live in
# the parent. mktemp gives each call its own directory anyway.
fresh_cache() {
  CACHE_N=$((CACHE_N + 1))
  mktemp -d "$WORK/cache-$CACHE_N-XXXXXX"
}

# ==========================================================================
# node
# ==========================================================================

run_node() {
  RAN=$((RAN + 1))
  binding="$ROOT/bindings/node"

  step "npm installer"
  (cd "$binding" && test -d node_modules/koffi) || (cd "$binding" && npm install --no-audit --no-fund >/dev/null 2>&1) || {
    say "node: no koffi and no registry; skipping this binding"
    return 0
  }

  # Run the binding the way a consumer would: a copy of the installed files in its own
  # directory. Left in cffi/, its search list still contains ../../build, so it would
  # load the library this repository just compiled and never notice the cache.
  app="$WORK/apps/node"
  rm -rf "$WORK/apps"
  mkdir -p "$app"
  cp "$binding/index.js" "$binding/index.mjs" "$binding/index.d.ts" "$binding/package.json" "$app/"
  cp -R "$binding/lib" "$binding/scripts" "$app/"
  ln -s "$binding/node_modules" "$app/node_modules"

  step "  postinstall fills the shared cache"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache" \
    node scripts/postinstall.js) >"$WORK/n1.log" 2>&1 || true
  log "$WORK/n1.log"
  expect_contains "postinstall reports where it put the library" "$HOST_SLUG $VERSION" "$WORK/n1.log"
  expect_file "cache holds the library" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME"
  expect_contains "install.json records the checksum" '"sha256"' "$cache/$VERSION/$HOST_SLUG/install.json"

  step "  require() reuses it"
  before=$(downloads 8741)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache" \
    node -e 'const {Ja3} = require("./index.js"); const j = new Ja3(); console.log("path", j.path); j.close();') \
      >"$WORK/n2.log" 2>&1 || true
  log "$WORK/n2.log"
  after=$(downloads 8741)
  [ "$before" = "$after" ] && ok "require() downloaded nothing ($after total)" \
    || fail "require() re-downloaded the archive ($before -> $after)"
  expect_contains "require() used the cached file" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME" "$WORK/n2.log"

  step "  a cold require() fetches by itself"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache" \
    node -e 'const {Ja3} = require("./index.js"); const j = new Ja3(); console.log("path", j.path); j.close();') \
      >"$WORK/n3.log" 2>&1 || true
  log "$WORK/n3.log"
  expect_file "cold require() placed the library" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME"
  expect_contains "cold require() loaded from the cache" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME" "$WORK/n3.log"

  step "  tampered archive"
  cache=$(fresh_cache)
  if (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_BAD JA3_CLIENT_CACHE_DIR="$cache" \
      node scripts/postinstall.js) >"$WORK/n4.log" 2>&1; then code=0; else code=$?; fi
  log "$WORK/n4.log"
  expect_contains "the mismatch quotes both hashes" "sha256 is" "$WORK/n4.log"
  expect_empty_dir "the mismatch installed nothing" "$cache"
  [ "$code" = 0 ] && ok "postinstall still exits 0" || fail "postinstall exited $code without JA3_CLIENT_STRICT"

  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_BAD JA3_CLIENT_CACHE_DIR="$cache" \
    node lib/native.js ensure) >"$WORK/n5.log" 2>&1 || true
  assert_contract_message "node's resolver" "$WORK/n5.log"

  step "  JA3_CLIENT_STRICT=1 makes the install fail"
  cache=$(fresh_cache)
  if (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_STRICT=1 JA3_CLIENT_BASE_URL=$BASE_BAD JA3_CLIENT_CACHE_DIR="$cache" \
      node scripts/postinstall.js) >"$WORK/n6.log" 2>&1; then code=0; else code=$?; fi
  log "$WORK/n6.log"
  [ "$code" != 0 ] && ok "strict postinstall exits $code" || fail "strict postinstall exited 0"

  step "  missing SHA256SUMS.txt"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_NOSUMS JA3_CLIENT_CACHE_DIR="$cache" \
    node lib/native.js ensure) >"$WORK/n7.log" 2>&1 || true
  log "$WORK/n7.log"
  assert_contract_message "node without sums" "$WORK/n7.log"

  step "  the archive is not in the release"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_NOASSET JA3_CLIENT_CACHE_DIR="$cache" \
    node lib/native.js ensure) >"$WORK/n8.log" 2>&1 || true
  log "$WORK/n8.log"
  assert_contract_message "node with a missing asset" "$WORK/n8.log"

  step "  JA3_CLIENT_OFFLINE=1"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_OFFLINE=1 JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache" \
    node lib/native.js ensure) >"$WORK/n9.log" 2>&1 || true
  log "$WORK/n9.log"
  assert_contract_message "node offline" "$WORK/n9.log"
  expect_empty_dir "offline touched nothing" "$cache"

  step "  JA3_CLIENT_LIB is an instruction, not a hint"
  (cd "$app" && env JA3_CLIENT_LIB="$WORK/definitely-not-here.so" JA3_CLIENT_CACHE_DIR="$WORK/unused" \
    node -e 'try { const {Ja3} = require("./index.js"); new Ja3(); } catch (e) { console.log(e.message) }') \
      >"$WORK/na.log" 2>&1 || true
  log "$WORK/na.log"
  expect_contains "a bad JA3_CLIENT_LIB raises" "definitely-not-here.so" "$WORK/na.log"
}

# ==========================================================================
# python
# ==========================================================================

run_python() {
  RAN=$((RAN + 1))
  binding="$ROOT/bindings/python"

  step "PyPI installer"

  # Same reason as for node: a copy in its own directory, so nothing in cffi/build/ is
  # on the search path and "found it" really means "the resolver put it in the cache".
  app="$WORK/apps/python"
  mkdir -p "$app"
  cp "$binding/ja3_client.py" "$binding/ja3_client_binaries.py" "$app/"

  step "  fetch fills the shared cache"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache" \
    python3 ja3_client_binaries.py ensure) >"$WORK/p1.log" 2>&1 || true
  log "$WORK/p1.log"
  expect_file "cache holds the library" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME"
  expect_contains "install.json records the checksum" '"sha256"' "$cache/$VERSION/$HOST_SLUG/install.json"

  step "  import reuses it"
  before=$(downloads 8741)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache" \
    python3 -c 'from ja3_client import Ja3; j = Ja3(); print("path", j.path); j.close()') \
      >"$WORK/p2.log" 2>&1 || true
  log "$WORK/p2.log"
  after=$(downloads 8741)
  [ "$before" = "$after" ] && ok "import downloaded nothing ($after total)" \
    || fail "import re-downloaded the archive ($before -> $after)"
  expect_contains "import used the cached file" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME" "$WORK/p2.log"

  step "  a cold import fetches by itself"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache" \
    python3 -c 'from ja3_client import Ja3; j = Ja3(); print("path", j.path); j.close()') \
      >"$WORK/p3.log" 2>&1 || true
  log "$WORK/p3.log"
  expect_file "cold import placed the library" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME"
  expect_contains "cold import loaded from the cache" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME" "$WORK/p3.log"

  step "  tampered archive"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_BAD JA3_CLIENT_CACHE_DIR="$cache" \
    python3 ja3_client_binaries.py fetch) >"$WORK/p4.log" 2>&1 || true
  log "$WORK/p4.log"
  expect_contains "the mismatch quotes both hashes" "sha256 is" "$WORK/p4.log"
  expect_empty_dir "the mismatch installed nothing" "$cache"
  assert_contract_message "python's resolver" "$WORK/p4.log"

  step "  missing SHA256SUMS.txt"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_NOSUMS JA3_CLIENT_CACHE_DIR="$cache" \
    python3 ja3_client_binaries.py fetch) >"$WORK/p5.log" 2>&1 || true
  log "$WORK/p5.log"
  assert_contract_message "python without sums" "$WORK/p5.log"

  step "  the archive is not in the release"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_BASE_URL=$BASE_NOASSET JA3_CLIENT_CACHE_DIR="$cache" \
    python3 ja3_client_binaries.py fetch) >"$WORK/p6.log" 2>&1 || true
  log "$WORK/p6.log"
  assert_contract_message "python with a missing asset" "$WORK/p6.log"

  step "  JA3_CLIENT_OFFLINE=1"
  cache=$(fresh_cache)
  (cd "$app" && env -u JA3_CLIENT_LIB JA3_CLIENT_OFFLINE=1 JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache" \
    python3 ja3_client_binaries.py ensure) >"$WORK/p7.log" 2>&1 || true
  log "$WORK/p7.log"
  assert_contract_message "python offline" "$WORK/p7.log"
  expect_empty_dir "offline touched nothing" "$cache"

  step "  JA3_CLIENT_LIB is an instruction, not a hint"
  (cd "$app" && env JA3_CLIENT_LIB="$WORK/definitely-not-here.so" JA3_CLIENT_CACHE_DIR="$WORK/unused" \
    python3 -c 'try:
    from ja3_client import Ja3; Ja3()
except Exception as e:
    print(type(e).__name__, e)') >"$WORK/p8.log" 2>&1 || true
  log "$WORK/p8.log"
  expect_contains "a bad JA3_CLIENT_LIB raises" "definitely-not-here.so" "$WORK/p8.log"
}

# ==========================================================================
# dotnet
# ==========================================================================

run_dotnet() {
  RAN=$((RAN + 1))

  step "NuGet installer"
  dotnet_bin=$(command -v dotnet 2>/dev/null || true)
  [ -n "$dotnet_bin" ] || [ -x /usr/local/share/dotnet/dotnet ] || {
    say "dotnet missing; skipping this binding"
    return 0
  }
  [ -n "$dotnet_bin" ] || dotnet_bin=/usr/local/share/dotnet/dotnet
  PATH="$(dirname "$dotnet_bin"):$PATH"
  export PATH

  pkg="$WORK/nupkg"
  rm -rf "$pkg" "$HOME/.nuget/packages/ja3-client"
  mkdir -p "$pkg"
  (cd "$ROOT/bindings/csharp" && dotnet pack -c Release -o "$pkg" >"$WORK/c0.log" 2>&1) || {
    log "$WORK/c0.log"
    fail "dotnet pack"
    return 0
  }
  # Match on the file name only: dotnet resolves and reprints the path, and any difference
  # in how it spells $pkg would make a full-path grep miss a build that worked.
  expect_contains "the package built clean" "ja3-client.$VERSION.nupkg" "$WORK/c0.log"

  tfm="net$(dotnet --version | cut -d. -f1)"
  app="$WORK/consumer"
  rm -rf "$app"
  mkdir -p "$app"
  cat > "$app/NuGet.config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$pkg" />
    <add key="nuget" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
EOF
  cat > "$app/consumer.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$tfm</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="ja3-client" Version="$VERSION" />
  </ItemGroup>
</Project>
EOF
  cat > "$app/Program.cs" <<'EOF'
using Ja3Client;

using var ja3 = new Ja3();
Console.WriteLine($"path {ja3.LibraryPath}");
EOF

  build() {  # build <log> [extra msbuild args]
    out=$1
    shift
    rm -rf "$app/bin" "$app/obj" "$HOME/.nuget/packages/ja3-client"
    (cd "$app" && dotnet build -v m "$@" >"$out" 2>&1) || true
  }

  step "  build fetches, verifies and copies next to the executable"
  cache=$(fresh_cache)
  export JA3_CLIENT_BASE_URL=$BASE_GOOD JA3_CLIENT_CACHE_DIR="$cache"
  build "$WORK/c1.log"
  log "$WORK/c1.log"
  expect_contains "the build succeeded" "Build succeeded" "$WORK/c1.log"
  expect_file "cache holds the library" "$cache/$VERSION/$HOST_SLUG/$LIB_NAME"
  expect_contains "install.json records the checksum" '"sha256"' "$cache/$VERSION/$HOST_SLUG/install.json"
  found=$(find "$app/bin" -name "$LIB_NAME" -print 2>/dev/null | head -1)
  [ -n "$found" ] && expect_file "output dir holds the library" "$found" \
    || fail "the library was not copied next to the executable"

  step "  a second build downloads nothing"
  before=$(downloads 8741)
  rm -rf "$app/bin" "$app/obj"
  (cd "$app" && dotnet build -v m >"$WORK/c2.log" 2>&1) || true
  after=$(downloads 8741)
  log "$WORK/c2.log"
  [ "$before" = "$after" ] && ok "warm cache downloaded nothing ($after total)" \
    || fail "warm cache re-downloaded the archive ($before -> $after)"
  expect_absent "no download happened" "Downloading from" "$WORK/c2.log"

  step "  tampered archive"
  export JA3_CLIENT_BASE_URL=$BASE_BAD
  cache=$(fresh_cache); export JA3_CLIENT_CACHE_DIR="$cache"
  build "$WORK/c3.log"
  log "$WORK/c3.log"
  expect_contains "the mismatch quotes both hashes" "SHA256 of" "$WORK/c3.log"
  expect_contains "a mismatch is a warning by default" "Build succeeded" "$WORK/c3.log"
  expect_empty_dir "the mismatch installed nothing" "$cache"

  step "  -p:Ja3ClientStrictFetch=true"
  cache=$(fresh_cache); export JA3_CLIENT_CACHE_DIR="$cache"
  build "$WORK/c4.log" -p:Ja3ClientStrictFetch=true
  expect_contains "strict fails the build" "error" "$WORK/c4.log"

  step "  missing SHA256SUMS.txt"
  export JA3_CLIENT_BASE_URL=$BASE_NOSUMS
  cache=$(fresh_cache); export JA3_CLIENT_CACHE_DIR="$cache"
  build "$WORK/c5.log"
  log "$WORK/c5.log"
  expect_contains "the missing sums file is named" "SHA256SUMS.txt" "$WORK/c5.log"
  expect_empty_dir "nothing was installed" "$cache"

  step "  the archive is not in the release"
  export JA3_CLIENT_BASE_URL=$BASE_NOASSET
  cache=$(fresh_cache); export JA3_CLIENT_CACHE_DIR="$cache"
  build "$WORK/c6.log" -p:Ja3ClientStrictFetch=true
  log "$WORK/c6.log"
  expect_contains "the missing asset is reported" "could not place $LIB_NAME" "$WORK/c6.log"

  step "  -p:Ja3ClientOffline=true"
  cache=$(fresh_cache)
  unset JA3_CLIENT_BASE_URL JA3_CLIENT_CACHE_DIR
  build "$WORK/c7.log" -p:Ja3ClientOffline=true -p:Ja3ClientCacheDir="$cache"
  log "$WORK/c7.log"
  expect_contains "offline says so" "no download was attempted" "$WORK/c7.log"
  expect_contains "offline points at the archive" "$ASSET" "$WORK/c7.log"
  expect_contains "offline still builds" "Build succeeded" "$WORK/c7.log"

  step "  an SDK RID with no archive"
  build "$WORK/c8.log" -p:NETCoreSdkPortableRuntimeIdentifier=linux-musl-x64
  log "$WORK/c8.log"
  expect_contains "the unknown RID is named" "linux-musl-x64" "$WORK/c8.log"
  expect_contains "an unknown RID still builds" "Build succeeded" "$WORK/c8.log"

  step "  JA3_CLIENT_LIB wins over the build"
  cache=$(fresh_cache)
  export JA3_CLIENT_LIB="$WORK/definitely-not-here.so" JA3_CLIENT_CACHE_DIR="$cache"
  build "$WORK/c9.log"
  log "$WORK/c9.log"
  expect_absent "an explicit JA3_CLIENT_LIB downloads nothing" "Downloading from" "$WORK/c9.log"
  (cd "$app" && dotnet run --no-build >"$WORK/ca.log" 2>&1) || true
  log "$WORK/ca.log"
  expect_contains "the binding refuses a bad JA3_CLIENT_LIB" "definitely-not-here.so" "$WORK/ca.log"
  unset JA3_CLIENT_LIB JA3_CLIENT_CACHE_DIR JA3_CLIENT_BASE_URL
}

# --- run -------------------------------------------------------------------

if command -v node    >/dev/null 2>&1; then run_node;    fi
if command -v python3 >/dev/null 2>&1; then run_python; fi
run_dotnet

step "Summary"
if [ -n "$FAILURES" ]; then
  say "the installers did not hold the contract:$FAILURES"
  exit 1
fi

[ "$RAN" -gt 0 ] || say "no toolchain was available - only the version checks ran"
say "all installer checks passed ($RAN binding group(s), $VERSION)"
