# Packaging the bindings for npm, PyPI and NuGet

The three bindings under `bindings/` are single files that expect a native library
to already exist somewhere. This document is the contract for turning them into
installable packages, and it is the only place the shared rules live - the Node,
Python and C# implementations follow it, so a change here has to be matched in all
three.

## What goes in a package, and what does not

A package ships the binding code and a resolver. It does **not** ship the library.
The Go build needs a cgo toolchain per target, the dylibs are tens of megabytes,
and a package that bundled one arch would fail on every other machine; so the
library comes from the GitHub Release for the matching version at install time.

| registry | package name | version | contents |
| --- | --- | --- | --- |
| npm | `ja3-client` | `X.Y.Z` | `index.js`, `index.mjs`, `index.d.ts`, `lib/native.js`, `scripts/postinstall.js`, `README.md` |
| PyPI | `ja3-client` | `X.Y.Z` | `ja3_client.py`, `ja3_client_binaries.py`, `README.md`, `LICENSE`, the `ja3-client` console script |
| NuGet | `ja3-client` | `X.Y.Z` | `lib/ja3-client-ffi.dll` (compiled from `Ja3.cs`), `build/ja3-client.targets`, `README.md`, `LICENSE` |

`koffi` is the npm package's only dependency; the PyPI and NuGet packages need
nothing beyond their own standard library / SDK, which is why those resolvers are
hand-written instead of shared.

Package version `X.Y.Z` means "the library built from tag `vX.Y.Z`", so a
`1.2.5` package downloads `v1.2.5`'s assets and the two versions can never drift
apart silently. `JA3_CLIENT_VERSION` overrides the library version alone when a
caller wants to test a release that is newer than the binding.

The version is written down four times, and `packages.yml` fails the run unless all
of them equal the tag: `package.json` (`"version"`), `ja3_client_binaries.py`
(`PACKAGE_VERSION`, what the resolver downloads), `pyproject.toml` (`version`, what
`python -m build` puts in the wheel name and what twine uploads) and
`Ja3Client.csproj` (`<Version>`). The two Python numbers are separate on purpose: the
first is a download target, the second is package metadata, and only the gate keeps
them in step.

## The release asset contract

```
https://github.com/smallerqiu/ja3-client/releases/download/v<version>/ja3-client-<version>-<os>-<arch>.zip
https://github.com/smallerqiu/ja3-client/releases/download/v<version>/SHA256SUMS.txt
```

`<os>-<arch>` is `darwin-amd64`, `darwin-arm64`, `linux-amd64`, `linux-arm64`,
`linux-armv7`, `linux-386`, `windows-amd64`, `windows-386`. Each zip contains one
directory `ja3-client-<version>-<os>-<arch>/` holding the library plus its header
and `smoke.py`:

```
ja3_client_<arch>.dylib   libja3_client_<arch>.so   ja3_client_<arch>.dll (+ .lib)
```

`SHA256SUMS.txt` is the output of `sha256sum *.zip`: `<64 hex>  <filename>`, and it
covers every archive in the release. Installers verify the archive against the
matching line before unpacking; a release that is missing either file is a hard
error with a message that says so, because a missing sums file is the one failure
mode a user cannot diagnose from a stack trace.

Linux archives are built in Debian bookworm containers, so they need glibc; musl
(Alpine) is not covered and has to build the library itself (`make -C cffi host`).

## The resolver contract

Every binding finds the library in this order, and stops at the first hit:

1. the `library_path` / `libraryPath` argument the caller passed;
2. `JA3_CLIENT_LIB` - an explicit file, which also means "never download";
3. the platform's own search dirs, which now include the shared cache below;
4. the archive in the cache, or a download into it (unless offline).

**Cache directory.** `JA3_CLIENT_CACHE_DIR` if set, else `$XDG_CACHE_HOME/ja3-client`
if set, else the platform default - `~/Library/Caches/ja3-client` on macOS,
`%LOCALAPPDATA%\ja3-client` on Windows, `~/.cache/ja3-client` everywhere else. All
three bindings use the same layout, so one download serves npm, pip and dotnet on
the same machine:

```
<cache>/<version>/<os>-<arch>/
    ja3_client_<arch>.dylib | libja3_client_<arch>.so | ja3_client_<arch>.dll
    install.json          {"version","asset","url","sha256","abi","installed_at",
                           "installed_by": "npm" | "pip" | "msbuild"}
```

**Environment.** One spelling per binding, all of them optional:

| variable | effect |
| --- | --- |
| `JA3_CLIENT_LIB` | use this exact file; never search, never download |
| `JA3_CLIENT_CACHE_DIR` | move the cache (also the place to point a CI mirror) |
| `JA3_CLIENT_VERSION` | library version to fetch, overriding the package version |
| `JA3_CLIENT_BASE_URL` | download base, default the URL above - set it to a local server to test |
| `JA3_CLIENT_REPO` | `owner/repo`, rewritten into the default base URL |
| `JA3_CLIENT_OFFLINE` | never touch the network; fail with the manual recipe instead |
| `JA3_CLIENT_STRICT` | make the install step fail loudly instead of warning |

**Download mechanics that are part of the contract**, because they are the parts
each binding tends to get wrong on its own:

- Follow redirects. `releases/download` answers 302 to a signed host, and the
  signature there is what makes the bytes tamper-evident in transit.
- Verify SHA-256 before extracting, and re-read the sums file per archive rather
  than trusting the first line.
- Write atomically: download to `<asset>.part`, then extract into a temporary
  directory and move the library into place, so an interrupted install cannot leave
  a truncated library that loads on some calls. A leftover `.part` is ignored.
- Reject a path that is not a regular file, and refuse to extract an entry whose
  name escapes the target directory (`..`, absolute paths) - the archive is trusted
  only after its hash matches, and the check costs three lines.
- Time out (the default is 60s per request) and retry once on a network error,
  because a release CDN hiccup should not look like a broken package.

**When the download runs.** npm has a `postinstall` hook, and NuGet has MSBuild
targets that run at restore, so both fetch during install. A wheel cannot execute
code at install time, so the Python binding fetches on first use instead - the
same resolver, just one call later, plus `python -m ja3_client_binaries fetch` for
people who want the bytes on disk before the process starts. Postinstall failure
must not break `npm install` unless `JA3_CLIENT_STRICT=1`: an app that pins
`JA3_CLIENT_LIB` to its own build would otherwise be un-installable.

**When the download is impossible**, every binding raises the same three lines:
the URL it tried, the arch it needs, and the manual recipe.

```
ja3-client: could not fetch the native library for linux-arm64 (v1.2.5).
  tried: https://github.com/smallerqiu/ja3-client/releases/download/v1.2.5/ja3-client-1.2.5-linux-arm64.zip
  offline? build it (make -C cffi host), or unzip a release archive and set JA3_CLIENT_LIB=/path/to/lib
```

## Checks that keep the contract honest

`cffi/test-installers.sh` is the offline end-to-end test (`make installers`). It

* asserts the five places the version and the ABI number are written down agree
  (`main.go`, the three bindings' resolvers, and the MSBuild targets) - a drift there
  makes a binding reject a library it should accept;
* builds the host library with `make host`, packages it with `package-release.sh`,
  and serves it from four local HTTP sites laid out like a GitHub Release: the good
  one, one whose archive no longer matches `SHA256SUMS.txt`, one with no sums file,
  and one with no archive;
* runs each binding **from a copy in a temporary directory**, because left in `cffi/`
  its search list still contains `../build`, and "found the library" would then mean
  nothing;
* walks the whole resolver contract per binding: install-time fetch, cache reuse with
  no second download, cold first-use fetch, checksum mismatch (warn by default, fatal
  under `JA3_CLIENT_STRICT` / `Ja3ClientStrictFetch`), missing sums, missing asset,
  `JA3_CLIENT_OFFLINE`, and `JA3_CLIENT_LIB` pointing at a file that is not there.

It needs a Go toolchain because it builds the library, and looks in the usual install
paths when `go` is not on PATH - a shell that never sourced `.zshrc` still gets a real
answer rather than a silent empty one. It skips any binding whose toolchain is missing,
so it can run on a machine with only one language installed. `make installers`
runs it; the `Packages` workflow runs it on Linux and macOS before assembling anything -
Windows and the 32-bit targets are built and export-checked by the `Release` workflow but
not executed there.

## Publishing

Nothing here publishes. `.github/workflows/packages.yml` builds and checks the
three packages on `workflow_dispatch`, and only uploads to the registries when the
run is started with `publish` checked **and** the version already exists as a
GitHub release with its assets - the packages are useless before that, since their
install step downloads from the release.

Between those two gates the workflow packs each binding the way a human would
(`npm pack`, `python -m build`, `dotnet pack`), reads the archive back to confirm the
installer's own files are in it and no native library accidentally is, and then
installs from those archives in clean projects against a stand-in release served on
127.0.0.1 - one cache directory shared by all three, so `install.json` from npm's
postinstall and the file Python and .NET load afterwards are the same record. A
package that resolves on the author's machine because of a stray `cffi/build` cannot
pass that job, which is the point of it.

The registry tokens are repository secrets (`NPM_TOKEN`, `PYPI_API_TOKEN`,
`NUGET_API_KEY`). Publishing order matters only for the notes: the GitHub release
first, then the three registries. The three names were checked on 2026-10-15 and
`ja3-client` was free on npm, PyPI and NuGet; re-check before the first real
publish, because a squatted name forces a rename of all three.

```sh
npm view ja3-client                                                 # 404 = still free
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/ja3-client/json
curl -s -o /dev/null -w '%{http_code}\n' https://api.nuget.org/v3/registration5-semver1/ja3-client/index.json
```
