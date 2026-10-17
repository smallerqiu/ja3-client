# cffi — the C ABI and the language bindings

`libja3-client` is the Go library compiled as a shared object (`-buildmode=c-shared`)
so Node, Python, C#, and anything else that can `dlopen` can impersonate a browser
without shipping Go.

Everything crosses the boundary as **one JSON string**, in and out. That keeps the
exported surface at six functions and a fixed shape, instead of a struct per option
that each language has to redeclare.

```
char* ja3_version(void);
char* ja3_request(char* payload);
char* ja3_session_new(char* payload);
char* ja3_session_request(unsigned long long id, char* payload);
char* ja3_session_close(unsigned long long id);
void  ja3_free(char* ptr);
```

`request` and `Free` are the old v1 names, kept as aliases of `ja3_request` and
`ja3_free` so existing code keeps loading. They return the **new** envelope, not
`ja3.Response` — see [Migrating from v1](#migrating-from-v1).

## Memory rules

1. Every returned `char*` is `malloc`'d inside the library and owned by the caller.
   Release it with `ja3_free`; nothing else can, and skipping it leaks one
   allocation per call.
2. Payload strings are copied on entry, so the caller may free or reuse them right
   after the call returns.
3. The JSON is pure text: the response body is either UTF-8 or base64 (see
   `body_base64`), never raw bytes, so it can never contain a NUL and truncate
   itself. This is deliberate — a `char*` ABI cannot carry binary.
4. The payload must be NUL-terminated UTF-8.

Binding note that bites people: with Python `ctypes`, do **not** set
`restype = c_char_p` — ctypes copies the C string into a `bytes` object and you lose
the pointer, so `ja3_free` has nothing valid to release and calling it aborts the
process (`SIGABRT`). Use `c_void_p` + `ctypes.string_at`, like
[`bindings/python/ja3_client.py`](bindings/python/ja3_client.py) does. koffi has the
same trap and solves it cleanly with a disposable type
([`bindings/node/index.js`](bindings/node/index.js)).

## Concurrency

`ja3_request` is safe from any thread; each call builds its own client. A session
handle is safe too — the Go client pools connections and guards its cookie jar, and
the handle table itself is mutex-guarded. The one rule: do not use a handle after
`ja3_session_close`, which returns `error_code: 4` rather than crashing.

## Payload fields

`snake_case` is the documented spelling. Every name is also accepted in its Go-field
form and in kebab-case (`WithHTTP3`, `not-follow-redirects`, `random_extension_order`
and `RandomExtensionOrder` all work), because callers coming from C# or Python
inevitably type what the language near them uses. **Unknown keys are never silently
dropped**: they come back in `warnings`.

Client-level (only read while the client is being built — `ja3_request`,
`ja3_session_new`):

| field | type | default | meaning |
| --- | --- | --- | --- |
| `impersonate` | string | `chrome_141` | profile id, e.g. `chrome_133`, `firefox_135`, `safari_170` |
| `ja3` | string | | raw JA3 string; wins over `impersonate` |
| `akamai` | string | | Akamai HTTP/2 settings string, used with `ja3` |
| `client_data` | object | | hand-built fingerprint (see below); wins over `ja3` |
| `proxy` | string | | `http://user:pass@host:port`, `socks5://host:port` |
| `source_ip` | string | | local address to bind |
| `timeout` | int | 30 | seconds |
| `force_http1` | bool | false | never use HTTP/2 |
| `with_http3` | bool or null | profile default | null keeps the default; **this is the switch people get wrong** — see [HTTP/3](#http3) |
| `random_extension_order` | bool | false | shuffle TLS extensions |
| `not_follow_redirects` | bool | false | stop at 3xx instead of following |
| `with_debug` | bool | false | library debug logging to stderr |
| `headers` | object | | session-level default headers |

Per-call (`ja3_request`, `ja3_session_request`):

| field | type | meaning |
| --- | --- | --- |
| `url` | string | required |
| `method` | string | default `GET` |
| `headers` | object | `{"name": "value"}`, `{"name": ["v1","v2"]}`, or `null` / `[]` to **remove** a header the session would send |
| `body` | string | UTF-8 request body |
| `body_base64` | string | binary body; wins over `body` |
| `timeout` | int | per-call override of the client timeout |
| `with_debug` | bool | |

`client_data` keys are the same snake_case spelling as `ja3.ClientData`:
`cipher_suites`, `curves`, `signature_hashed`, `tls_extension_order`,
`http_2_setting`, `http_2_window_update`, `http_2_pseudo_header_order`,
`http_2_priorities`, `tls_version`, `tls_grease`, `ech`, `alps`, `cert_compression`,
`tls_trust_anchors`, `user_agent`, `with_http3`, … Unknown keys there are reported too
(`unknown client_data option "..." ignored`).

Two header defaults the FFI installs, because they decide whether the response is
readable:

* `user-agent` from the chosen profile — and it survives every request. The Go
  client only applies its default headers when a request carries **no** headers at
  all, so the bindings layer per-call headers over the recorded session base instead
  of replacing it.
* `accept-encoding: identity` — the transport does not transparently decompress, so
  a negotiated `br`/`gzip` body would arrive as base64 the caller cannot read. Set
  `accept-encoding` yourself (or remove it with `null`) if you want to handle
  compression, and read `body_base64` plus `content-encoding` in that case.

## Response envelope

Same shape for every export. Fields with nothing to say are omitted rather than
emitted as empty.

```json
{
  "error_code": 0,
  "ok": true,
  "status_code": 200,
  "protocol": "HTTP/2.0",
  "headers": { "Content-Type": ["application/json"] },
  "set_cookies": ["session=1; Path=/"],
  "body": "...",              // or:
  "body_base64": "...",       // when body_binary is true
  "body_binary": true,
  "body_size": 1233,
  "warnings": [],
  "session": 1,               // ja3_session_new / ja3_session_request
  "version": "1.2.4",         // ja3_version
  "abi": 2,
  "build_time": "2026-10-15T02:33:01Z"
}
```

`headers` keeps repeated headers as a list, and `set_cookies` is the raw
`Set-Cookie` sequence in order — flattening them into a map loses both attributes and
ordering, which is exactly what a login flow needs.

### Error codes

| `error_code` | name | meaning |
| --- | --- | --- |
| 0 | `OK` | the call worked; check `status_code` for the HTTP result |
| 1 | `NIL_ARGUMENT` | missing payload, empty `url`, null pointer |
| 2 | `BAD_JSON` | payload is not JSON, a field has the wrong type, or `body_base64` is not base64 |
| 3 | `SESSION_INIT` | the client could not be built (bad proxy URL, unknown profile that errors) |
| 4 | `INVALID_HANDLE` | session id is 0, closed, or never opened |
| 5 | `REQUEST` | transport / request-construction failure |
| 6 | `READ_BODY` | response arrived but the body could not be read |
| 7 | `MARSHAL` | the envelope itself failed (should not happen) |
| 8 | `PANIC` | a Go panic was recovered so it could not abort the host process |

`ok` is `error_code == 0`. An HTTP 404 is `ok: true` with `status_code: 404` — a
status is data, not a failure. Bindings raise their typed error on non-zero
`error_code` only (`Ja3Error` / `Ja3Exception`), with `.raise_for_status()` /
`.RaiseForStatus()` available for the status.

## HTTP/3

`h3` in the TLS ALPN list is **not** set by every profile: the anchors that set
`WithHttp3` are `Chrome_132`, `Chrome_136`, `Chrome_137_ios`, `Chrome_150`,
`Chrome_152`, `Edge_136`, `Opera_120` and `Brave_1_8` (and `c(new, anchor)` passes
it down to their descendants), so the Chrome/Edge/Opera ids advertise
`h3, h2, http/1.1` while Firefox, Safari and the rest send `h2, http/1.1`.
Consequences worth knowing before you compare a fingerprint against browserleaks
(measured 2026-10-15 with `chrome_141`):

* The ALPN segment of `ja4` depends on who computes it: browserleaks reads the
  **first** protocol and reports `t13d1516h3`, while tls.peet.ws reports
  `t13d1516h2` for the same ClientHello. A real Chrome on TCP has ALPN
  `h2, http/1.1` (its own captures say so), so the deviation shows up on
  browserleaks as `h3` where the browser says `h2`. The cipher and extension
  hashes, the normalized JA3 and the Akamai hash are unaffected.
* When a server answers `h3` over TCP ALPN, the client opens a **separate QUIC
  connection** (`roundtripper.go:287`), and that connection is built from a plain
  `tls.Config` with no `ClientHelloID` in it — so its ClientHello is the library's
  own, not the browser's you asked to impersonate. Treat HTTP/3 as advertised, not
  impersonated. That path is also not uniformly reliable: some hosts end up as
  `error_code: 5` with an `H3 error` or a timeout.
* `"with_http3": false` removes `h3` from the ALPN list and puts browserleaks'
  `ja4` back to `h2`. Use it to compare like for like against a browser capture, and
  leave the default alone otherwise: `h3` on is what was measured in production. At
  roughly a million concurrent requests against Cloudflare-fronted sites, the same
  Chrome profile with `h3` removed drew clearly more challenges and errors, and they
  dropped to almost none as soon as `h3` went back on — including on the versions
  whose own captures do not list `h3`. A fingerprint site disagreeing with you is
  not the same thing as a site blocking you.

## Building

```sh
make host        # this machine only -> build/<os>/<name>
make all         # darwin + linux + windows, needs the cross compilers listed in Makefile
make docker      # full matrix in throwaway containers (needs Docker)
make test        # the FFI contract tests - offline, uses httptest
make smoke       # load the host library and check the ABI, no network (Python)
make node-smoke  # same checks through koffi (Node)
make check       # host build + go tests + both smokes + python/node/c# examples
make package     # zip whatever is in build/ into dist/, the way CI does
```

`GOWORK=off` is exported by the Makefile: `cffi/` is its own main module with
`replace github.com/smallerqiu/ja3-client => ../`, and the repository's `go.work`
would take over module resolution and hide that replace. Because the replace points
at the checkout, a build here ships the code you just tested instead of an old
published tag — which was the bug in the previous setup, where `cffi/go.mod` pinned
`v1.2.3` and every shipped artifact carried that release's library.

Release artifacts are named per platform and architecture, and the bindings search
for exactly these (`JA3_CLIENT_LIB` overrides everything):

```
build/darwin/ja3_client_arm64.dylib      build/darwin/ja3_client_amd64.dylib
build/linux/libja3_client_amd64.so       build/linux/libja3_client_arm64.so
build/linux/libja3_client_armv7.so       build/linux/libja3_client_386.so
build/windows/ja3_client_amd64.dll       build/windows/ja3_client_386.dll
build/*/ja3_client*.h                    the generated C header
```

Linux builds carry a `soname` equal to their own file name; the previous build
claimed `libja3-client.so`, a file that never exists on disk. Windows builds also
emit `ja3_client_<arch>.lib`, the import library MSVC needs to link against the dll.

### Verifying a build

`bindings/python/smoke.py` and `bindings/node/smoke.js` load a library and check the
contract without making a request, so they run with no internet and no credentials:

```sh
python3 bindings/python/smoke.py build/darwin/ja3_client_arm64.dylib
node bindings/node/smoke.js build/linux/libja3_client_amd64.so
```

They assert that the ABI number matches the binding, that the version was stamped
(`-X main.Version`), that a malformed payload comes back as `error_code: 2` instead of
killing the host process, that a missing url is `error_code: 1`, and that a session
handle closes once and then reports `INVALID_HANDLE`.

Every release archive ships `smoke.py` next to the library, so a download can prove
itself before it reaches your code:

```sh
unzip ja3-client-1.2.7-linux-amd64.zip
cd ja3-client-1.2.7-linux-amd64 && python3 smoke.py
```

### CI and releases

* [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on pushes and pull
  requests: module hygiene (gofmt, `go mod tidy -diff`, and the two opposite `replace`
  rules that keep `go get` working while keeping the artifacts honest), the package README
  gate (`make docs-check`), the consumer-side typecheck of the Node declarations
  (`make types-check`), the Go tests on Linux/macOS/Windows, then the library build, both
  smokes, and a package → unpack → load round trip.
* [`.github/workflows/release.yml`](../.github/workflows/release.yml) runs on a tag push
  or a published release. It calls the same scripts this folder does —
  `./build-docker.sh <version> --only <target>` for Linux and Windows, `make darwin` on a
  macOS runner — verifies that each artifact exports all six ABI functions, packages with
  `package-release.sh`, and attaches the zips plus `checksums.txt` to the release.
* `package-release.sh` refuses to package an artifact whose architecture disagrees with
  its file name. That check exists because `make darwin-amd64` without `GOARCH` silently
  produced an arm64 dylib named `ja3_client_amd64.dylib`.

## Bindings

| language | path | dependency | verified |
| --- | --- | --- | --- |
| Python | [`bindings/python/ja3_client.py`](bindings/python/ja3_client.py) | none (ctypes, stdlib) | yes, 3.13 + dylib |
| Node | [`bindings/node/index.js`](bindings/node/index.js) | `koffi` | yes, Node 25 + dylib |
| C# | [`bindings/csharp/Ja3.cs`](bindings/csharp/Ja3.cs) | none (P-Invoke) | yes, .NET 9 + dylib |

The three examples
([`example.py`](bindings/python/example.py), [`example.js`](bindings/node/example.js),
[`example/Program.cs`](bindings/csharp/example/Program.cs)) do the same sequence of
calls on purpose, so a difference between bindings is visible immediately. They need
internet, because they really fetch pages; the offline
[`smoke.py`](bindings/python/smoke.py) / [`smoke.js`](bindings/node/smoke.js) pair
covers the same wiring without a request.

```python
from ja3_client import Ja3

ja3 = Ja3()
print(ja3.get("https://tls.browserleaks.com/json", impersonate="chrome_133").json()["ja3n_hash"])

with ja3.session(impersonate="chrome_133") as s:      # pool + cookie jar reused
    s.get("https://example.com/")
    s.get("https://example.com/about")
```

```js
const { Ja3 } = require('./index.js');

const ja3 = new Ja3();
const res = ja3.get('https://tls.browserleaks.com/json', { impersonate: 'chrome_133' });
const session = ja3.session({ impersonate: 'chrome_133' });
session.post('https://example.com/login', { user: 'a' });
session.close();
```

```csharp
using var ja3 = new Ja3();
var res = ja3.Get("https://tls.browserleaks.com/json", new RequestOptions { Impersonate = "chrome_133" });

using var session = ja3.OpenSession(new SessionOptions { Impersonate = "chrome_133" });
session.Get("https://example.com/");
```

Python and C# need no packages at all. Node needs
[`koffi`](https://koffi.dev) (`npm install koffi`); `ffi-napi` and
`node-ffi-ref` were not chosen because they do not build on modern Node without a
node-gyp toolchain. C# uses `NativeLibrary.SetDllImportResolver`, so the library file
does not need to sit next to the executable — see the search order in `Ja3.cs`.

`ja3_version()` reports `abi`, and each binding refuses to load a library whose `abi`
is not the one it was written against. Bump `ABIVersion` in `main.go` and the
constants in the three bindings together when the shape changes.

## Migrating from v1

The v1 export was `request(payload) -> ja3.Response`, i.e. `{Body, StatusCode,
Headers, Cookies}` with `Cookies` flattened into a map and no error channel at all.
The v2 envelope renames everything to snake_case and adds `error_code`, `protocol`,
`set_cookies`, `body_base64`, `warnings`.

Breaking changes to expect when you keep calling `request`:

* `Body` → `body`; `StatusCode` → `status_code`; `Cookies` → `set_cookies` (a list of
  raw `Set-Cookie` values).
* `error_code` is set on failure — v1 wrote the failure text into `Body`, which made
  an error indistinguishable from a page that happened to contain that sentence.
* Sessions exist now: `ja3_session_new` + `ja3_session_request` reuse one connection
  pool and cookie jar. v1's `request` rebuilt a client per call and closed the idle
  connections, so nothing was ever reused.

`cffi/main.py` (the v1 ctypes wrapper) is gone; `bindings/python/ja3_client.py`
replaces it.
