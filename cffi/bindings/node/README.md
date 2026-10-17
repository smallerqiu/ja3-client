# ja3-client (Node.js)

Browser TLS/H2/H3 fingerprint impersonation from Node, through a koffi binding to the
Go shared library. The ABI contract - payload keys, response envelope, error codes -
lives in [../../README.md](../../README.md); this file only covers installing the
binary that binding needs.

```js
const { Ja3 } = require('ja3-client');

const ja3 = new Ja3();
const res = ja3.request('https://tls.browserleaks.com/json', { impersonate: 'chrome_133' });

console.log(res.json().ja3n_hash);
```

## Where the library comes from

`npm install` runs `scripts/postinstall.js`, which downloads
`ja3-client-<version>-<os>-<arch>.zip` from this repository's GitHub Release for the
package version, checks it against the release's `SHA256SUMS.txt`, and unpacks the
library into a cache shared with the Python and C# bindings:

```
~/.cache/ja3-client/<version>/<os>-<arch>/   (macOS: ~/Library/Caches, Windows: %LOCALAPPDATA%)
```

A postinstall that cannot reach GitHub prints why and still exits 0, because an app
that ships its own build should not be un-installable over a CDN hiccup. The library
is then fetched on first use instead; `JA3_CLIENT_STRICT=1` makes the install fail
loudly, which is what CI should set.

At runtime the binding looks for, in order: the `libraryPath` you pass to `new
Ja3()`, `JA3_CLIENT_LIB`, a library beside it or under `cffi/build`, and the cache. If
all of those miss it calls the resolver once more.

## Knobs

| variable | effect |
| --- | --- |
| `JA3_CLIENT_LIB` | use this exact file; never search, never download |
| `JA3_CLIENT_CACHE_DIR` | move the cache (also how you point CI at a mirror) |
| `JA3_CLIENT_VERSION` | library version to fetch, overriding the package version |
| `JA3_CLIENT_BASE_URL` | download root, for a mirror or an offline test server |
| `JA3_CLIENT_REPO` | `owner/repo` if you build the library from a fork |
| `JA3_CLIENT_OFFLINE=1` | never touch the network; fail with the manual recipe |
| `JA3_CLIENT_STRICT=1` | make postinstall failure fatal |

Handy commands:

```sh
node lib/native.js print-url   # which archive this machine wants
node lib/native.js ensure      # fetch it now, print the path
node lib/native.js status      # version, slug, cache dir, what is present
node smoke.js                  # offline ABI check against any library path
```

## No network, no GitHub

Build the library yourself and pin it:

```sh
git clone https://github.com/smallerqiu/ja3-client && cd ja3-client/cffi && make host
export JA3_CLIENT_LIB="$PWD/build/$(uname -s | tr A-Z a-z)/ja3_client_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').dylib"
```

or unzip a release archive and point `JA3_CLIENT_LIB` at the file inside. Linux
archives are built against glibc (Debian bookworm); on musl (Alpine) build the library
yourself.
