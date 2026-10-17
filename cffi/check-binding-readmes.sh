#!/usr/bin/env bash
# Gate the three package READMEs against the ABI they document.
#
# The problem this exists for: each binding's README used to say "the ABI contract lives
# in ../../README.md", and a relative link does not exist on an npm, PyPI or NuGet page -
# so the only readers who never see the field list are the ones who installed the package.
# The READMEs are self-sufficient now, which means they can silently fall behind ffi.go on
# their own. This compares them to the source of truth on every CI run.
#
#   ./check-binding-readmes.sh          from cffi/ or anywhere
#
# What has to be in every package README:
#   * every payload field of ffiRequest, in the snake_case spelling the wire accepts
#   * every response field of ffiResponse that a caller can read
#   * every error-code name
#   * the environment knobs that binding actually reads
#   * at least five runnable examples, and no relative link a registry page cannot follow
set -euo pipefail

cd "$(dirname "$0")"

readmes="bindings/node/README.md bindings/python/README.md bindings/csharp/README.md"

# -- the contract, read out of the Go source ------------------------------------------

# json tags of one struct: awk stops at the struct's own closing brace, so neither the
# helper types below ffiRequest nor its unexported fields get mixed in.
json_tags() {
  awk -v type="$1" '
    $0 ~ "^type " type " struct" { inside = 1; next }
    inside && /^}/                { exit }
    inside                        { print }
  ' ffi.go | sed -n 's/.*json:"\([a-z_]*\).*/\1/p' | sort -u
}

payload_fields=$(json_tags ffiRequest)
# version/abi/build_time answer ja3_version(), not a request; the READMEs cover them as
# libraryVersion / version() / SdkVersion instead of as response fields.
response_fields=$(json_tags ffiResponse | grep -vE '^(version|abi|build_time)$')

# The uppercase names come from the map each binding already ships, so a new code has to
# be added where the errors are actually raised before this file can complain about it.
error_names=$(sed -n '/^ERROR_CODES = {/,/^}/p' bindings/python/ja3_client.py |
  sed -n 's/.*: "\([A-Z_]*\)".*/\1/p' | sort -u)

# -- per-binding extras ----------------------------------------------------------------
# Spelling each binding's own public surface has to state, beyond the shared contract.
extras_node='ABI_VERSION ERROR_CODES libraryVersion buildTime checkAbi raiseForStatus
  Ja3Error INVALID_HANDLE JA3_CLIENT_LIB JA3_CLIENT_STRICT setCookies body_base64
  ja3.fetch session.fetch maxConcurrency UV_THREADPOOL_SIZE'
extras_python='ABI_VERSION ERROR_CODES check_abi raise_for_status Ja3Error body_base64
  ja3_client_binaries print-url'
extras_csharp='AbiVersion Ja3Exception Ja3ErrorCode RaiseForStatus BodyBase64 SetCookies
  Ja3ClientSkipNativeFetch Ja3ClientStrictFetch runtimes'

# -- the checks ------------------------------------------------------------------------

fail() { printf '%s\n' "$@" >&2; exit 1; }

missing=""
for readme in $readmes; do
  [ -f "$readme" ] || fail "check-binding-readmes: $readme does not exist"

  case "$readme" in
    *node*) extras=$extras_node ;;
    *python*) extras=$extras_python ;;
    *csharp*) extras=$extras_csharp ;;
  esac

  for field in $payload_fields $response_fields $error_names $extras; do
    grep -qF -- "$field" "$readme" || missing="$missing
  $readme: $field"
  done

  # A relative link is the exact bug this gate was written for.
  if grep -qE '\]\((\.\./|\./)' "$readme"; then
    missing="$missing
  $readme: link that a registry page cannot resolve:
    $(grep -nE '\]\((\.\./|\./)' "$readme" | sed 's/^/      /')"
  fi

  # Five examples is the promise the READMEs make to somebody who reads instead of greps.
  # A fenced block opens with ```language and closes with a bare ```, so the bare ones
  # count finished examples.
  sections=$(grep -c '^## ' "$readme" || true)
  snippets=$(sed -n '/^## Recipes$/,/^## [^R]/p' "$readme" | grep -c '^```$' || true)

  if [ "${snippets:-0}" -lt 5 ]; then
    missing="$missing
  $readme: the Recipes section has $snippets complete examples, not the 5 it promises"
  fi

  if [ "$sections" -lt 9 ]; then
    missing="$missing
  $readme: $sections sections, which is not a reference"
  fi
done

if [ -n "$missing" ]; then
  cat >&2 <<EOF
check-binding-readmes: a package README does not document the ABI it ships.

Every field, error code and knob below is part of the contract and has to appear in the
README that a registry page shows - npm/PyPI/NuGet strip relative links, so pointing at
cffi/README.md from there is the same as saying nothing.

Add the missing rows to the table in each README, or, if the field really is not meant
for that language, say so there in prose.$missing
EOF
  exit 1
fi

# -- and the version strings the READMEs quote ------------------------------------------
# The install-time resolver asks for the release that matches the package version, so a
# README that shows a different one teaches the wrong command.
version=$(sed -n 's/.*"version": "\(.*\)",/\1/p' bindings/node/package.json | head -1)
for file in bindings/python/pyproject.toml bindings/csharp/Ja3Client.csproj; do
  found=$(sed -n 's/.*<Version>\(.*\)<\/Version>.*/\1/p; s/^version = "\(.*\)"/\1/p' "$file" | head -1)

  [ "$found" = "$version" ] ||
    fail "check-binding-readmes: $file says $found, npm says $version"
done

for readme in $readmes; do
  # `|| true` because grep exits 1 when a README quotes no archive at all, and pipefail
  # would read that as the gate failing.
  { grep -oE 'ja3-client-[0-9]+\.[0-9]+\.[0-9]+' "$readme" || true; } |
    while read -r quoted; do
      [ "$quoted" = "ja3-client-$version" ] ||
        { echo "check-binding-readmes: $readme quotes $quoted, the package is $version" >&2; exit 1; }
    done
done

echo "check-binding-readmes: $(printf '%s\n' $payload_fields | wc -l | tr -d ' ') payload fields, \
$(printf '%s\n' $response_fields | wc -l | tr -d ' ') response fields, \
$(printf '%s\n' $error_names | wc -l | tr -d ' ') error codes present in all three READMEs (v$version)."
