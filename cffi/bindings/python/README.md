# ja3-client (Python)

Browser TLS/H2/H3 fingerprint impersonation from Python, through a `ctypes` binding to
the Go shared library. Pure standard library - no build step, no dependencies. The ABI
contract (payload keys, response envelope, error codes) is in
[cffi/README.md](../README.md); this file covers installing the binary the binding needs.

```python
from ja3_client import Ja3

ja3 = Ja3()
resp = ja3.request("https://tls.browserleaks.com/json", impersonate="chrome_153")
print(resp.json()["ja3n_hash"])

with ja3.session(impersonate="chrome_133") as session:
    session.get("https://example.com/")            # same pool + cookie jar
```

## Where the library comes from

`pip install ja3-client` installs binding code only. A wheel cannot run code at install
time, so the native library is fetched the first time `Ja3()` is constructed: the
resolver downloads `ja3-client-<version>-<os>-<arch>.zip` from this repository's GitHub
Release for the installed version, checks it against the release's `SHA256SUMS.txt`, and
unpacks the library into a cache shared with the Node and C# bindings:

```
~/.cache/ja3-client/<version>/<os>-<arch>/    (macOS: ~/Library/Caches, Windows: %LOCALAPPDATA%)
```

To fetch it explicitly - before a container build, or on a machine that will later be
offline:

```sh
ja3-client ensure          # or: python -m ja3_client_binaries ensure
ja3-client print-url       # the archive this machine wants
ja3-client status          # version, slug, cache dir, what is present
```

At runtime the binding looks for, in order: the `library_path` you pass to `Ja3()`,
`JA3_CLIENT_LIB`, a library beside it or under `cffi/build`, any version in the shared
cache, and only then a download.

## Knobs

| variable | effect |
| --- | --- |
| `JA3_CLIENT_LIB` | use this exact file; never search, never download |
| `JA3_CLIENT_CACHE_DIR` | move the cache (also how you point CI at a mirror) |
| `JA3_CLIENT_VERSION` | library version to fetch, overriding the package version |
| `JA3_CLIENT_BASE_URL` | download root, for a mirror or an offline test server |
| `JA3_CLIENT_REPO` | `owner/repo` if you build the library from a fork |
| `JA3_CLIENT_OFFLINE=1` | never touch the network; fail with the manual recipe |

## No network, no GitHub

Build it and pin it, or unzip a release archive and point `JA3_CLIENT_LIB` at the file
inside - every archive carries `smoke.py`, which proves the download offline:

```sh
git clone https://github.com/smallerqiu/ja3-client && cd ja3-client/cffi && make host
export JA3_CLIENT_LIB="$PWD/build/darwin/ja3_client_arm64.dylib"   # linux: libja3_client_amd64.so
```

Linux archives are built against glibc (Debian bookworm); on musl (Alpine) build the
library yourself.
