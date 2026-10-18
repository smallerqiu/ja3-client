# ja3-client (Python)

Browser TLS/HTTP2/HTTP3 fingerprint impersonation from Python. The handshake is the part
that gets you blocked — the ClientHello's cipher order, extensions and ALPN list, plus
the HTTP/2 `SETTINGS` frame and the pseudo-header order — and those are not headers, so
no amount of `User-Agent` faking changes them. This package drives a Go library
(`libja3-client`) that replays a captured Chrome / Firefox / Safari profile, through
`ctypes`. Standard library only, no build step, no dependencies.

```python
from ja3_client import Ja3

ja3 = Ja3()
resp = ja3.get("https://tls.browserleaks.com/json", impersonate="chrome_153")
print(resp.json()["ja3n_hash"])          # the fingerprint the site read from your TLS
```

`pip install ja3-client` needs Python >= 3.9 and installs binding code plus one console
script; the native library for your OS/CPU is fetched on first use and cached (see
[Where the library comes from](#where-the-library-comes-from)). Type hints are inline, so
mypy works without a stub package.

## What you can call

| call | returns | |
| --- | --- | --- |
| `Ja3(library_path=None, search_paths=(), check_abi=True)` | `Ja3` | loads the library; `check_abi=False` skips the ABI mismatch guard |
| `ja3.request(url, *, method="GET", headers=None, body=None, **options)` | `Response` | one-shot request: builds a client, uses it once, drops idle connections |
| `ja3.get(url, **options)` | `Response` | `request` with `method="GET"` |
| `ja3.post(url, body=None, **options)` | `Response` | `request` with `method="POST"`; `body` may be `str`, `bytes`, `dict`, `list`, number or `bool` |
| `ja3.session(**options)` | `Session` | opens a client that keeps its connection pool and cookie jar; usable as a context manager |
| `ja3.version()` | `str` | version stamped into the library at build time |
| `ja3.path` | `str` | the library file actually loaded |
| `ja3.close()` | | for symmetry with the other bindings; Python has nothing to release. Close your sessions. |

Module-level shortcuts do the same thing through one lazily created, process-wide
instance, which is the shortest way to fire a single request:

```python
import ja3_client

print(ja3_client.get("https://example.com/", impersonate="firefox_135").status_code)
print(ja3_client.version())
```

`ABI_VERSION` (a number) and `ERROR_CODES` (`{0: "OK", …}`) are exported too, along with
`Ja3`, `Ja3Error`, `Response` and `Session`.

## Options

Keyword arguments map onto the payload fields, and the spelling is the same snake_case
the ABI documents. Names are matched loosely — `with_http3`, `WithHTTP3` and even
`"with-http3"` (only reachable through `**{"with-http3": False}`, since Python identifiers
cannot contain a hyphen) all land on the same field — so a key copied from another
language's docs still works. A keyword the library does not know is **not** dropped: it
comes back in `resp.warnings`. `None` values are omitted, which is how you leave a
tri-state field at its default.

Client-level — only read while the client is being built, i.e. by `request()` and
`session()`. A session request ignores them and the binding drops them from the payload:

| keyword | type | default | meaning |
| --- | --- | --- | --- |
| `impersonate` | str | `chrome_155` | profile id: `chrome_133`, `chrome_153`, `firefox_135`, `safari_17_0`, … |
| `ja3` | str | | raw JA3 string; wins over `impersonate` |
| `akamai` | str | | Akamai HTTP/2 settings string, used together with `ja3` |
| `client_data` | dict | | hand-built fingerprint (see below); wins over `ja3` |
| `proxy` | str | | scheme required: `http://user:pass@host:port`, `https://host:port`, `socks5://host:port` (`socks5h` too). A missing scheme is `error_code: 5`, not a silent no-proxy. |
| `source_ip` | str | | local address to bind |
| `timeout` | int | 30 | seconds; `0` keeps the library default |
| `force_http1` | bool | false | never negotiate HTTP/2 |
| `with_http3` | bool \| None | profile default | `None` keeps the profile's choice, `False` removes `h3` from ALPN — see [HTTP/3](#http3) |
| `random_extension_order` | bool | false | shuffle the TLS extension order |
| `not_follow_redirects` | bool | false | stop at a 3xx instead of following it |
| `with_debug` | bool | false | library debug logging to stderr |
| `headers` | dict | | default headers for every request on this client/session |

Per-call:

| keyword | type | meaning |
| --- | --- | --- |
| `url` | str | required; `""` raises `Ja3Error` with `error_code: 1` |
| `method` | str | default `GET`, upper-cased for you |
| `headers` | dict | `{"name": "value"}`, `{"name": ["v1", "v2"]}` (one header line per value — an echo site usually shows them joined with a comma), or `None` as the value to **remove** a header the session would otherwise send |
| `body` | str \| bytes \| dict \| list \| int \| float \| bool | `bytes` is sent as-is; a `dict`/`list` is serialised with `json.dumps(..., ensure_ascii=False)`; a number or bool becomes its text |
| `body_base64` | str | raw base64 body; wins over `body` |
| `timeout` | int | per-call override of the client timeout |
| `with_debug` | bool | |

Per-call `headers` are merged **over** the client's `headers`, not instead of them — and
that merge is what keeps the profile's `user-agent` alive when you add one header of your
own. Two defaults the library installs for you, because the response is unreadable
without them:

* `user-agent` taken from the chosen profile.
* `accept-encoding: identity`. The transport does not decompress, so a negotiated `br`
  or `gzip` body would arrive as base64 you cannot read. Set `accept-encoding` yourself
  (or remove it with `headers={"accept-encoding": None}`) when you want to handle
  compression, and read `resp.body` plus the `content-encoding` header in that case.

`client_data` keys are the same snake_case spelling the Go `ja3.ClientData` struct uses —
`cipher_suites`, `curves`, `signature_hashed`, `tls_extension_order`, `http_2_setting`,
`http_2_window_update`, `http_2_pseudo_header_order`, `http_2_priorities`, `tls_version`,
`tls_grease`, `ech`, `alps`, `cert_compression`, `tls_trust_anchors`, `user_agent`,
`with_http3` — and an unknown key there is reported as a warning too
(`unknown client_data option "…" ignored`). Four spellings that are easy to get wrong:

| key | wants | |
| --- | --- | --- |
| `cipher_suites` | comma-separated **constant names** | `TLS_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`; numbers (`4865`) are not looked up |
| `curves` | **colon**-separated names | `X25519MLKEM768:X25519:P256:P384`; at least `tls_key_shares_limit` (default 3) of them |
| `signature_hashed` | comma-separated names **or hex ids** | `ECDSAWithP256AndSHA256,…` or `0403,0804,0401`; hex, so a decimal `1027` from a capture will not parse |
| `tls_version` | `any`, `1.3`, `1.2` or `1.1` | required — an empty one is `error_code: 5` with `ja3Str tls version error` |

## Response

Every call returns a `Response`, a decoded view of one JSON envelope. Reading a property
never touches the library again; the envelope stays whole in `resp.raw`.

| attribute | type | |
| --- | --- | --- |
| `status_code` | int | HTTP status; `0` if the envelope had none |
| `protocol` | str | `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0` |
| `headers` | `dict[str, list[str]]` | repeated headers stay a list, original casing |
| `set_cookies` | `list[str]` | raw `Set-Cookie` values, in order — a login flow needs the attributes and the sequence, which a map loses |
| `warnings` | `list[str]` | unknown options, ignored `client_data` keys |
| `body_size` | int | bytes |
| `body` | `bytes` | decoded from `body_base64` when the body was binary |
| `session` | int | the handle that made this request, `0` for one-shot calls |
| `raw` | `dict` | the envelope as parsed |
| `text` | `str` property | body decoded as UTF-8, undecodable bytes replaced |
| `content` | `bytes` property | the body, spelled the way `requests` spells it |
| `json()` | `Any` | `json.loads(text)` |
| `header(name, default=None)` | `str \| None` | first value, case-insensitive |
| `ok` | bool property | `200 <= status_code < 400`. Note this is **not** the envelope's `ok`, which means "the call worked"; an HTTP 404 is a successful call. |
| `raise_for_status()` | `Response` | raises `Ja3Error` (`error_code: 5`) unless `ok` |

`repr()` gives you `<Response 200 HTTP/2.0 1233B>`. A non-zero `error_code` raises instead
of returning anything, so a `Response` in your hands always means the transport succeeded.

`resp.raw` is the envelope exactly as the ABI defines it: `error_code`, `error`, `ok`,
`status_code`, `protocol`, `headers`, `set_cookies`, `body`, `body_base64`, `body_binary`,
`body_size`, `warnings`, `session` — plus `version`, `abi` and `build_time`, which only the
version call fills. `body_binary: True` is the library saying "the body only exists as
`body_base64`", which `resp.body` already decoded for you.

## Sessions

`ja3.session()` builds one client and keeps it: connection pool, cookie jar, default
headers, profile. Requests on it reuse that state, which is the difference between one
page load and a login flow.

```python
with ja3.session(impersonate="chrome_133", timeout=20) as session:
    session.get("https://example.com/")          # sets a cookie
    session.get("https://example.com/account")   # sends it back, over the same connection

session.closed       # True - the context manager called close()
session.handle       # the number the library gave this client
session.get("https://example.com/")   # Ja3Error, error_code 4
```

| call | |
| --- | --- |
| `session.request(url, *, method="GET", headers=None, body=None, **options)`, `session.get(url, **options)`, `session.post(url, body=None, **options)` | same per-call keywords as `ja3.request` |
| `session.close()` | idempotent; also called by `__exit__` and a best-effort `__del__` |

Requests are safe from any thread — the Go client pools connections and guards its cookie
jar — but a handle you have closed is not: it reports `error_code: 4` (`INVALID_HANDLE`)
rather than crashing the interpreter.

## Errors

Everything raises `Ja3Error`, a `RuntimeError` subclass carrying the library's own code:

```python
from ja3_client import Ja3, Ja3Error

try:
    ja3.get("", impersonate="chrome_133")          # empty url
except Ja3Error as error:
    print(error.error_code, error.name)            # 1 NIL_ARGUMENT
    print(error.payload)                           # the full envelope
```

| `error_code` | `name` | when |
| --- | --- | --- |
| 1 | `NIL_ARGUMENT` | missing payload, empty `url`, null pointer |
| 2 | `BAD_JSON` | a field has the wrong type, or `body_base64` is not base64 |
| 3 | `SESSION_INIT` | the client could not be built (bad proxy URL, a profile that errors) |
| 4 | `INVALID_HANDLE` | the session id is 0, closed, or never opened |
| 5 | `REQUEST` | transport or request-construction failure; also what `raise_for_status()` raises |
| 6 | `READ_BODY` | the response arrived but its body could not be read |
| 7 | `MARSHAL` | the envelope itself failed — should not happen |
| 8 | `PANIC` | a Go panic was recovered so it could not abort your process |

Two of those depend on which call you made, because a one-shot builds the client inside the
request while a session has already built it:

* bad `body_base64` → `2` on a session request, `5` on a one-shot;
* a proxy URL the parser rejects → `3` from `session()`, `5` from `request()`.

`0` (`OK`) never raises. The status is separate data: `raise_for_status()` exists for when
you want a 404 to be an exception too.

## HTTP/3

Some profiles advertise `h3` in their ALPN list and some do not — the Chrome, Edge, Opera
and Brave anchors do (`h3, h2, http/1.1`), Firefox and Safari do not (`h2, http/1.1`).
Two things follow, and both surprise people:

* Fingerprint sites disagree about what to report. browserleaks reads the **first** ALPN
  entry and shows `ja4` as `t13d1516h3` for `chrome_141`, while tls.peet.ws reports
  `t13d1516h2` for the same ClientHello. `with_http3=False` puts browserleaks back to
  `h2`, which is what you want when comparing against a browser capture.
* When a server answers `h3` over TCP ALPN, the client opens a separate QUIC connection
  whose ClientHello is the library's own, **not** the browser you asked to impersonate.
  Treat HTTP/3 as advertised, not impersonated; some hosts also end up as `error_code: 5`
  with an `H3 error` or a timeout.

Leave the default alone otherwise. Under heavy concurrent traffic against
Cloudflare-fronted sites, the same Chrome profile with `h3` removed drew clearly more
challenges and errors than with it on.

## Where the library comes from

A wheel cannot run code at install time, so the native library is fetched the first time
`Ja3()` is constructed: the resolver downloads `ja3-client-<version>-<os>-<arch>.zip` from
this repository's GitHub Release for the installed version, checks it against that
release's `SHA256SUMS.txt`, and unpacks the library into a cache shared with the Node and
C# packages:

```
~/.cache/ja3-client/<version>/<os>-<arch>/    (macOS: ~/Library/Caches, Windows: %LOCALAPPDATA%)
```

Fetch it explicitly instead — before a container build, or on a machine that will later be
offline:

```sh
ja3-client ensure          # or: python -m ja3_client_binaries ensure
ja3-client print-url       # the archive this machine wants
ja3-client status          # version, slug, cache dir, what is present
```

At runtime the binding looks for, in order: the `library_path` you passed to `Ja3()`,
`JA3_CLIENT_LIB`, a library beside it or under `cffi/build`, any version in the shared
cache, and only then a download.

A path that is not a file raises `Ja3Error` from the constructor, with the path in the
message. A file that exists but is not a loadable library raises whatever `ctypes` raises
(`OSError` on a bad architecture, on a zip you unzipped into the wrong place) — the load
fails before the ABI check can run.

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
inside — every archive ships `smoke.py`, which proves the download offline:

```sh
git clone https://github.com/smallerqiu/ja3-client && cd ja3-client/cffi && make host
export JA3_CLIENT_LIB="$PWD/build/darwin/ja3_client_arm64.dylib"   # linux: libja3_client_amd64.so
python3 bindings/python/smoke.py            # checks the ABI, makes no request
```

Linux archives are built against glibc (Debian bookworm); on musl (Alpine) build the
library yourself, and there is no archive for 32-bit ARM Windows.

## Recipes

Fingerprint, and what the site actually saw:

```python
seen = ja3.get("https://tls.browserleaks.com/json", impersonate="chrome_153").json()
# The keys that site answers with: user_agent, ja4, ja4_r, ja4_o, ja4_ro, ja3_hash,
# ja3_text, ja3n_hash, ja3n_text, akamai_hash, akamai_text.
print(seen["ja3n_hash"], seen["akamai_hash"], seen["ja4"])
```

POST JSON, keeping the profile's own headers:

```python
resp = ja3.post("https://httpbin.org/post",
                {"q": "中文", "page": 1},
                impersonate="chrome_133",
                headers={"content-type": "application/json"})
print(resp.json()["json"])                 # echoed back by httpbin
```

Login flow: cookies and keep-alive across requests.

```python
with ja3.session(impersonate="chrome_133", headers={"x-app": "demo"}) as session:
    session.get("https://httpbin.org/cookies/set?name=value")   # 302, then /cookies
    cookies = session.get("https://httpbin.org/cookies")        # same jar, same connection
    print(cookies.json()["cookies"])                            # {'name': 'value'}

    # Per-call headers merge over the session's, so x-app is still on this request.
    authed = session.get("https://httpbin.org/basic-auth/u/p",
                         headers={"authorization": "Basic dTpw"})    # 'u' / 'p' base64-ed
    print(authed.status_code, authed.json()["authenticated"])        # 200 True
```

(httpbin's `/basic-auth` only answers `GET`; a `POST` to it is a 405 from the server, which
`raise_for_status()` would then turn into a `Ja3Error` with `error_code: 5`.)

Binary in, binary out:

```python
icon = ja3.get("https://www.google.com/favicon.ico")
print(icon.body_size, icon.header("content-type"), icon.content[:4].hex())

ja3.post("https://httpbin.org/post", open("payload.bin", "rb").read())   # bytes go out as-is
```

Through a proxy, staying on HTTP/1.1, and letting a 3xx be data rather than a detour:

```python
probe = ja3.request("https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.com%2F",
                    impersonate="firefox_135",
                    proxy="http://user:pass@127.0.0.1:8888",
                    force_http1=True, with_http3=False, not_follow_redirects=True)
# headers keeps the wire spelling ('Location'), so use header() for a case-insensitive
# lookup instead of headers.get('location').
print(probe.status_code, probe.header("location"))
```

The proxy part of that is worth spelling out, because a proxy is where the impersonated
request stops and ordinary transport starts:

* the URL needs a scheme — `http://`, `https://`, `socks5://` or `socks5h://`.
  `127.0.0.1:8888` is refused with `error_code: 5` and a "specify full url" message.
* userinfo in the URL becomes one `Proxy-Authorization: Basic …` header on the `CONNECT`;
  without userinfo the header is still sent, empty. A proxy that challenges you and gets
  that empty header answers 407, which surfaces as `error_code: 5` with
  `Proxy responded with non 200 code: 407 …` — not as a 407 response you can read.
* `http://` targets go through the same `CONNECT` tunnel as `https://` ones, so the proxy
  sees `CONNECT host:80` rather than an absolute-form request line.
* what the *origin* sees stays the impersonated profile: the proxy is one hop, the
  ClientHello and headers are still the browser's.

A fingerprint built by hand instead of picked from a profile:

```python
hand = ja3.get("https://tls.browserleaks.com/json", client_data={
    "tls_version": "1.3",                                          # required
    "cipher_suites": "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,"
                     "TLS_CHACHA20_POLY1305_SHA256,"
                     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
                     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "curves": "X25519MLKEM768:X25519:P256:P384",                   # : separated, >= 3
    "signature_hashed": "0403,0804,0401",                          # hex, as a capture writes it
    "http_2_setting": "1:65536;2:0;4:6291456;6:262144",
    "http_2_window_update": 15663105,
    "cert_compression": "brotli",
    "tls_grease": True, "alps": True, "ech": True, "compressed": True,
    "user_agent": "HandBuilt/1.0",
})
print(hand.json()["ja3_hash"], hand.json()["akamai_hash"], hand.json()["user_agent"])
```

A typo is reported rather than ignored:

```python
t = ja3.get("https://httpbin.org/get", impersonate="chrome_133", with_http4=True)
print(t.warnings)      # ['unknown option "with_http4" ignored']
```

## Vendoring instead of packaging

`ja3_client.py` is one file with no dependencies: copy it next to your code and point
`JA3_CLIENT_LIB` (or `Ja3(library_path=...)`) at a library you built with
`make -C cffi host`. The GitHub release archives carry that same file.

## Further reading

The full ABI — the six export functions, the JSON envelope, the C header — is documented
in [cffi/README.md](https://github.com/smallerqiu/ja3-client/blob/master/cffi/README.md),
and how the three packages are built and shipped is in
[PACKAGING.md](https://github.com/smallerqiu/ja3-client/blob/master/cffi/PACKAGING.md).
This file is the whole API for the common cases and does not depend on either.
