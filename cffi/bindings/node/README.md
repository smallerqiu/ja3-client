# ja3-client (Node.js)

Browser TLS/HTTP2/HTTP3 fingerprint impersonation from Node. The handshake is the part
that gets you blocked — the ClientHello's cipher order, extensions and ALPN list, plus
the HTTP/2 `SETTINGS` frame and the pseudo-header order — and those are not headers, so
no amount of `User-Agent` faking changes them. This package drives a Go library
(`libja3-client`) that replays a captured Chrome / Firefox / Safari profile, over
[`koffi`](https://koffi.dev). There is no compile step: `npm install` fetches the
prebuilt library for your OS and CPU on install or first use.

```js
const { Ja3 } = require('ja3-client');   // ESM: import { Ja3 } from 'ja3-client'

const ja3 = new Ja3();
const res = ja3.get('https://tls.browserleaks.com/json', { impersonate: 'chrome_153' });

console.log(res.json().ja3n_hash);       // the fingerprint the site read from your TLS
```

`npm install ja3-client` requires Node >= 16 and installs one dependency (`koffi`).
TypeScript types ship with the package.

## CommonJS and ESM

Both spellings are the same binding — the package maps `require` to `index.js` and `import`
to an `index.mjs` wrapper around it, so nothing about the download, the ABI guard or the
session pool changes with the module system:

```js
// ESM: a .mjs file, or a package.json with "type": "module"
import { Ja3, Ja3Error, ABI_VERSION, ERROR_CODES } from 'ja3-client';
import ja3client from 'ja3-client';              // the same exports as an object

const ja3 = new Ja3();
const res = ja3.get('https://tls.browserleaks.com/json', { impersonate: 'chrome_153' });
const page = await ja3.fetch('https://tls.browserleaks.com/json', { impersonate: 'chrome_153' });

console.log(res.json().ja3n_hash, page.json().ja3n_hash, ABI_VERSION, ja3client.Ja3 === Ja3);
```

Named imports are complete: `Ja3`, `Session`, `Response`, `Ja3Error`, `ABI_VERSION`,
`ERROR_CODES`. `get`/`request`/`post` are synchronous and return a `Response`; `fetch` is the
one that answers a promise. See [Sync and async](#sync-and-async) — and no, `await`ing
`request()` is not the async form: a `Response` is not a promise, so awaiting it hands the
same object back after your loop has been stopped for the whole request.

TypeScript resolves the declarations through the same map, under `node16`, `nodenext` and
`bundler` module resolution alike, for `require` and `import` both; the repository
typechecks a consumer against the packaged files on every push (`make types-check`), so a
`.d.ts` that fails your build fails ours first. `Buffer` in the signatures is Node's, so a
project needs `@types/node` (or `skipLibCheck`) like any other Node library.

## What you can call

| call | returns | |
| --- | --- | --- |
| `new Ja3({ libraryPath, checkAbi, maxConcurrency })` | `Ja3` | loads the library; `checkAbi: false` skips the ABI mismatch guard, `maxConcurrency` sets the async ceiling ([Sync and async](#sync-and-async)) |
| `ja3.request(url, options)` | `Response` | one-shot request: builds a client, uses it once, drops idle connections. **Synchronous** — the event loop waits for it |
| `ja3.get(url, options)` | `Response` | `request` with `method: 'GET'` |
| `ja3.post(url, body, options)` | `Response` | `request` with `method: 'POST'`; `body` may be a string, `Buffer`, `Uint8Array`, object, array or number |
| `ja3.fetch(url, options)` | `Promise<Response>` | the same call on a worker thread: identical options, identical `Response`, identical `Ja3Error` — it only rejects instead of throwing |
| `ja3.session(options)` | `Session` | opens a client that keeps its connection pool and cookie jar |
| `ja3.maxConcurrency` | number | read or move the async ceiling; a non-positive integer throws `Ja3Error` (`errorCode: 1`) |
| `ja3.version()` / `ja3.libraryVersion` | `string` | version stamped into the library at build time |
| `ja3.buildTime` | `string` | when that library was built (UTC, RFC 3339) |
| `ja3.path` | `string` | the library file actually loaded |
| `ja3.close()` | | for parity with the other bindings; releases nothing today, since `koffi` keeps its handle for the process. Close your sessions. |

`ABI_VERSION` (a number) and `ERROR_CODES` (`{0: 'OK', …}`) are exported too.

## Sync and async

`request`, `get` and `post` are synchronous: the FFI call does not come back until the
response is in, and nothing else in your process runs while it waits. `fetch` runs the same
export on a worker thread — same options, same `Response`, same `Ja3Error`, but your event
loop keeps turning:

```js
const pages = await Promise.all(
  urls.map((url) => ja3.fetch(url, { impersonate: 'chrome_153' })));
```

Measured on one machine (8 cores, Node 25.8.2, koffi 3.3.3) against a handler that sleeps
150 ms, counting how many times a `setInterval` in the same process fired while the calls
were outstanding:

| what | wall | loop ticks while waiting |
| --- | --- | --- |
| 4 × `request()`, sequential | 623 ms | 0 — the loop was stopped |
| 4 × `fetch()`, concurrent | 154 ms | 8 |
| 12 × `fetch()`, concurrent | 464 ms | 21 |

Two ceilings decide how much of that third row overlaps, and they are not the same number:

| knob | default | what it caps |
| --- | --- | --- |
| `ja3.maxConcurrency` | 256 | how many `fetch` calls may be outstanding or queued at once |
| `UV_THREADPOOL_SIZE` | 4 | how many of them are actually in flight at the same instant |

`maxConcurrency` exists because koffi's async queue is hard-capped (`max_async_calls`, 256
by default, 4096 absolute) and it **rejects** past it: a 600-call burst on this library came
back as 256 responses and 344 "Too many asynchronous calls are running". The binding waits
for a slot instead, so `Promise.all` over 10 000 URLs resolves rather than failing — and a
call that does get a slot and then fails gives it back, which is the whole reason the gate is
in the binding rather than left to koffi:

```js
ja3.maxConcurrency;                    // 256
ja3.maxConcurrency = 64;               // fewer calls issued, more of them waiting
const other = new Ja3({ maxConcurrency: 512 });
```

The ceiling is process-wide, not per instance — it guards koffi's async queue, which every
`Ja3` object in the process shares — and only `fetch` and `session.fetch` are counted, so a
synchronous call neither waits for a slot nor takes one.

`UV_THREADPOOL_SIZE` is the one people miss, and it is Node's knob, not the library's: koffi
dispatches through libuv, so the default pool runs four requests at a time and the other
eight in that 12-call row spent their time queued. The same 12 calls finished in 157 ms with
`UV_THREADPOOL_SIZE=16`, and 24 concurrent calls went from four-at-a-time (3.6 s, peak 4 in
flight) to all-at-once (0.6 s, peak 24) at 64. It tracks the pool in both directions — `=2`
really does run two at a time, `=1` runs one — so this is the pool deciding, not the CPU
count (koffi's own documentation says the worker threads follow the number of cores, which is
not what this binding sees on Node). Set it in the environment before anything else in the
process has used the pool:

```sh
UV_THREADPOOL_SIZE=32 node server.js
```

Raising it is not free: those threads are shared with `fs`, `zlib` and DNS lookups, each
outstanding async call preallocates 128 KiB of stack and 128 KiB of heap inside koffi, and a
call holds its thread for its full duration — so a `fetch` with no `timeout` you forgot is a
worker you did not get back.

What `fetch` is **not**: a Go-side pool or a licence to open a hundred thousand sockets from
one Node process. It keeps your loop responsive while the library works. If the job is a
crawl rather than a page, the batch belongs on the Go side (many requests per cross-language
call, connections and profiles reused in one client), not in N promises.

One last consequence of the sync path, because it bites people writing tests: if the server
you are calling lives in the same process, `request()` stops the loop that would answer it.
The pair deadlocks until the Go timeout fires (30 s by default) and you get `errorCode: 5`
with `Client.Timeout exceeded while awaiting headers` — which reads like a server bug and is
a stopped event loop. `fetch()` against that same in-process server returns 200.

And one consequence of the async path, which bites people writing scripts: **a process that
has used `fetch()` does not shut itself down.** The loop drains, `beforeExit` fires, and then
the process just stays there, indefinitely. It is the Go runtime's thread handover during
shutdown, not this binding's queue or a leaked socket — one `ja3_version()` call on a worker
thread is enough to cause it, while the same async call into a plain C library through koffi
exits by itself. Nothing is pending, and a server that never intends to exit will never notice.
A program that reaches its last line has to say it means it:

```js
const pages = await Promise.all(urls.map((url) => ja3.fetch(url)));
console.log(pages.length, 'done');

process.exit(0);            // without this the process sits there, finished
```

## Options

One options object carries both the client-level and the call-level fields. Keys are the
`snake_case` names below — the same spelling the ABI documents — and every one of them is
also accepted in `kebab-case` or Go/`PascalCase` form (`withHTTP3` reaches `with_http3`),
so a name copied from another language's docs still works. A key the library does not
know is **not** dropped: it comes back in `response.warnings`.

Client-level — only read while the client is being built, i.e. by `request()`, `fetch()` and
`session()`. A session request ignores them and the binding drops them from the payload:

| key | type | default | meaning |
| --- | --- | --- | --- |
| `impersonate` | string | `chrome_155` | profile id: `chrome_133`, `chrome_153`, `firefox_135`, `safari_17_0`, … |
| `ja3` | string | | raw JA3 string; wins over `impersonate` |
| `akamai` | string | | Akamai HTTP/2 settings string, used together with `ja3` |
| `client_data` | object | | hand-built fingerprint (see below); wins over `ja3` |
| `proxy` | string | | scheme required: `http://user:pass@host:port`, `https://host:port`, `socks5://host:port` (`socks5h` too). A missing scheme is `errorCode: 5`, not a silent no-proxy. |
| `source_ip` | string | | local address to bind |
| `timeout` | number | 30 | seconds; `0` keeps the library default |
| `force_http1` | boolean | false | never negotiate HTTP/2 |
| `with_http3` | boolean \| undefined | profile default | `undefined` keeps the profile's choice, `false` removes `h3` from ALPN — see [HTTP/3](#http3) |
| `random_extension_order` | boolean | false | shuffle the TLS extension order |
| `not_follow_redirects` | boolean | false | stop at a 3xx instead of following it |
| `with_debug` | boolean | false | library debug logging to stderr |
| `headers` | object | | default headers for every request on this client/session |

Per-call:

| key | type | meaning |
| --- | --- | --- |
| `url` | string | required; `''` throws `Ja3Error` with `errorCode: 1` |
| `method` | string | default `GET`, upper-cased for you |
| `headers` | object | `{'name': 'value'}`, `{'name': ['v1', 'v2']}` (one header line per value — an echo site usually shows them joined with a comma), or `null` as the value to **remove** a header the session would otherwise send |
| `body` | string \| Buffer \| Uint8Array \| object \| number \| boolean | `Buffer`/`Uint8Array` is sent as-is; an object or array is `JSON.stringify`ed |
| `body_base64` | string | raw base64 body; wins over `body`, and the way to send bytes without a `Buffer` |
| `timeout` | number | per-call override of the client timeout |
| `with_debug` | boolean | |

Per-call `headers` are merged **over** the client's `headers`, not instead of them — and
that merge is what keeps the profile's `user-agent` alive when you add one header of your
own. Two defaults the library installs for you, because the response is unreadable
without them:

* `user-agent` taken from the chosen profile.
* `accept-encoding: identity`. The transport does not decompress, so a negotiated `br`
  or `gzip` body would arrive as base64 you cannot read. Set `accept-encoding` yourself
  (or remove it with `headers: {'accept-encoding': null}`) when you want to handle
  compression, and read `res.body` plus the `content-encoding` header in that case.

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
| `tls_version` | `any`, `1.3`, `1.2` or `1.1` | required — an empty one is `errorCode: 5` with `ja3Str tls version error` |

## Response

Every call returns a `Response`, a decoded view of one JSON envelope. Reading a property
never touches the library again; the envelope stays whole in `res.raw`.

| property | type | |
| --- | --- | --- |
| `statusCode`, `status` | number | HTTP status; `0` if the envelope had none |
| `protocol` | string | `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0` |
| `headers` | `Record<string, string[]>` | repeated headers stay a list, original casing |
| `setCookies` | string[] | raw `Set-Cookie` values, in order — a login flow needs the attributes and the sequence, which a map loses |
| `warnings` | string[] | unknown options, ignored `client_data` keys |
| `bodySize` | number | bytes |
| `body` | `Buffer` | decoded from `body_base64` when the body was binary |
| `session` | number | the handle that made this request, `0` for one-shot calls |
| `raw` | object | the envelope as parsed |
| `text()` | string | body as UTF-8 |
| `json()` | any | `JSON.parse(text())` |
| `header(name)` | string \| undefined | first value, case-insensitive |
| `ok` | boolean | `200 <= statusCode < 400`. Note this is **not** the envelope's `ok`, which means "the call worked"; an HTTP 404 is a successful call. |
| `raiseForStatus()` | `Response` | throws `Ja3Error` (`errorCode: 5`) unless `ok` |

A non-zero `error_code` throws instead of returning anything, so a `Response` in your
hands always means the transport succeeded.

`res.raw` is the envelope exactly as the ABI defines it, snake_case and all:
`error_code`, `error`, `ok`, `status_code`, `protocol`, `headers`, `set_cookies`, `body`,
`body_base64`, `body_binary`, `body_size`, `warnings`, `session` — plus `version`, `abi`
and `build_time`, which only the version call fills. `body_binary: true` is the library
saying "the body only exists as `body_base64`", which `res.body` already decoded for you.

## Sessions

`ja3.session()` builds one client and keeps it: connection pool, cookie jar, default
headers, profile. Requests on it reuse that state, which is the difference between one
page load and a login flow.

```js
const session = ja3.session({ impersonate: 'chrome_133', timeout: 20 });

session.get('https://example.com/');         // sets a cookie
session.get('https://example.com/account');  // sends it back, over the same connection

session.handle;   // the number the library gave this client
session.closed;   // false until close()

session.close();
session.get('https://example.com/');         // throws Ja3Error, errorCode 4
```

| member | |
| --- | --- |
| `request(url, options)`, `get(url, options)`, `post(url, body, options)` | same per-call options as `ja3.request` |
| `fetch(url, options)` | the non-blocking form, on the same handle: same pool, same cookie jar, answers a promise |
| `close()` | idempotent; safe to call twice |

`Session` is safe to use from any thread — the Go client pools connections and guards its
cookie jar — but a handle you have closed is not: it reports `error_code: 4`
(`INVALID_HANDLE`) rather than crashing your process.

Concurrent `session.fetch()` calls are the normal way to use one: a page's requests, or a
crawl of one host, over a single set of cookies.

```js
const session = ja3.session({ impersonate: 'chrome_153', headers: { 'x-app': 'demo' } });

const [home, account] = await Promise.all([
  session.fetch('https://example.com/'),
  session.fetch('https://example.com/account'),
]);

session.close();
```

## Errors

Everything throws `Ja3Error`, a real `Error` subclass carrying the library's own code and
the envelope it came back with:

```js
const { Ja3, Ja3Error } = require('ja3-client');
const ja3 = new Ja3();

try {
  ja3.get('', { impersonate: 'chrome_133' });      // empty url
} catch (error) {
  if (error instanceof Ja3Error) {
    console.log(error.errorCode, error.codeName);  // 1 'NIL_ARGUMENT'
    console.log(error.payload);                    // the full envelope, text and all
  }
}
```

| `errorCode` | `codeName` | when |
| --- | --- | --- |
| 1 | `NIL_ARGUMENT` | missing payload, empty `url`, null pointer |
| 2 | `BAD_JSON` | a field has the wrong type, or `body_base64` is not base64 |
| 3 | `SESSION_INIT` | the client could not be built (bad proxy URL, a profile that errors) |
| 4 | `INVALID_HANDLE` | the session id is 0, closed, or never opened |
| 5 | `REQUEST` | transport or request-construction failure; also what `raiseForStatus()` throws |
| 6 | `READ_BODY` | the response arrived but its body could not be read |
| 7 | `MARSHAL` | the envelope itself failed — should not happen |
| 8 | `PANIC` | a Go panic was recovered so it could not abort your process |

`fetch` changes nothing about the object, only about how it reaches you: the same `Ja3Error`
with the same `errorCode` and `payload`, arriving as a rejected promise. An unhandled one is
an unhandled rejection, so a `try` around the `await` or a `.catch()` is not optional in an
app you want to stay up.

Two of those depend on which call you made, because a one-shot builds the client inside the
request while a session has already built it:

* bad `body_base64` → `2` on a session request, `5` on a one-shot;
* a proxy URL the parser rejects → `3` from `session()`, `5` from `request()`.

`0` (`OK`) never throws. The status is separate data: `raiseForStatus()` exists for when
you want a 404 to be an exception too. `JA3_CLIENT_STRICT` is a different kind of strict —
it only affects the install-time library fetch, below.

## HTTP/3

Some profiles advertise `h3` in their ALPN list and some do not — the Chrome, Edge, Opera
and Brave anchors do (`h3, h2, http/1.1`), Firefox and Safari do not (`h2, http/1.1`). Two
things follow, and both surprise people:

* Fingerprint sites disagree about what to report. browserleaks reads the **first** ALPN
  entry and shows `ja4` as `t13d1516h3` for `chrome_141`, while tls.peet.ws reports
  `t13d1516h2` for the same ClientHello. `{with_http3: false}` puts browserleaks back to
  `h2`, which is what you want when comparing against a browser capture.
* When a server answers `h3` over TCP ALPN, the client opens a separate QUIC connection
  whose ClientHello is the library's own, **not** the browser you asked to impersonate.
  Treat HTTP/3 as advertised, not impersonated; some hosts also end up as `errorCode: 5`
  with an `H3 error` or a timeout.

Leave the default alone otherwise: under heavy concurrent traffic against Cloudflare-fronted
sites, the same Chrome profile with `h3` removed drew clearly more challenges and errors than
with it on.

## Where the library comes from

The npm package ships binding code only — an install hook cannot be relied on for every
consumer, and a binary in git would bloat the repository. `npm install` runs
`scripts/postinstall.js`, which downloads `ja3-client-<version>-<os>-<arch>.zip` from this
repository's GitHub Release for the installed version, verifies it against that release's
`SHA256SUMS.txt`, and unpacks the library into a cache the Python and C# packages share:

```
~/.cache/ja3-client/<version>/<os>-<arch>/    (macOS: ~/Library/Caches, Windows: %LOCALAPPDATA%)
```

A postinstall that cannot reach GitHub prints why and still exits 0, so a CDN hiccup
cannot make your app un-installable; the library is then fetched on first use instead. Set
`JA3_CLIENT_STRICT=1` in CI if you would rather the install failed loudly.

At runtime the binding looks for, in order: the `libraryPath` you passed to `new Ja3()`,
`JA3_CLIENT_LIB`, a library beside the package or under `cffi/build`, any version in the
shared cache — and only then does it download one.

A path that is not a file is a `Ja3Error` from the constructor and the message names the
path. A path that is a file but not a loadable library is koffi's own `Error` — the load
fails before the ABI check can run, so there is no envelope to wrap.

```sh
node lib/native.js ensure      # fetch now, print the path (do this before a container build)
node lib/native.js print-url   # the archive this machine wants
node lib/native.js status      # version, slug, cache dir, what is present
node smoke.js                  # offline ABI check against a library path
node test-async.js             # offline check of fetch(): the gate, the worker threads, the error shape
```

## Knobs

| variable | effect |
| --- | --- |
| `JA3_CLIENT_LIB` | use this exact file; never search, never download |
| `JA3_CLIENT_CACHE_DIR` | move the cache (also how you point CI at a mirror) |
| `JA3_CLIENT_VERSION` | library version to fetch, overriding the package version |
| `JA3_CLIENT_BASE_URL` | download root, for a mirror or an offline test server |
| `JA3_CLIENT_REPO` | `owner/repo` if you build the library from a fork |
| `JA3_CLIENT_OFFLINE=1` | never touch the network; fail with the manual recipe |
| `JA3_CLIENT_STRICT=1` | make a failed postinstall fatal |

## No network, no GitHub

Build it and pin it:

```sh
git clone https://github.com/smallerqiu/ja3-client && cd ja3-client/cffi && make host
export JA3_CLIENT_LIB="$PWD/build/$(uname -s | tr A-Z a-z)/ja3_client_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').dylib"
```

or unzip a release archive and point `JA3_CLIENT_LIB` at the file inside — every archive
carries `smoke.py`, which proves the download offline. Linux archives are built against
glibc (Debian bookworm); on musl (Alpine) build the library yourself, and there is no
archive for 32-bit ARM Windows.

## Recipes

Fingerprint, and what the site actually saw:

```js
const { Ja3 } = require('ja3-client');
const ja3 = new Ja3();

const seen = ja3.get('https://tls.browserleaks.com/json', { impersonate: 'chrome_153' })
  .json();
// The keys that site answers with: user_agent, ja4, ja4_r, ja4_o, ja4_ro, ja3_hash,
// ja3_text, ja3n_hash, ja3n_text, akamai_hash, akamai_text.
console.log(seen.ja3n_hash, seen.akamai_hash, seen.ja4);
```

POST JSON, keeping the profile's own headers:

```js
const res = ja3.request('https://httpbin.org/post', {
  impersonate: 'chrome_133',
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: { q: '中文', page: 1 },          // an object is JSON.stringify-ed for you
});
console.log(res.json().json);           // echoed back by httpbin
```

Login flow: cookies and keep-alive across requests.

```js
const session = ja3.session({ impersonate: 'chrome_133', headers: { 'x-app': 'demo' } });
try {
  session.get('https://httpbin.org/cookies/set?name=value');   // 302, then /cookies
  const cookies = session.get('https://httpbin.org/cookies');  // same jar, same connection
  console.log(cookies.json().cookies);                         // { name: 'value' }

  // Per-call headers merge over the session's, so x-app is still on this request.
  const authed = session.get('https://httpbin.org/basic-auth/u/p', {
    headers: { authorization: 'Basic dTpw' },                  // 'u' / 'p' base64-ed
  });
  console.log(authed.statusCode, authed.json().authenticated); // 200 true
} finally {
  session.close();
}
```

(httpbin's `/basic-auth` only answers `GET`; a `POST` to it is a 405 from the server, which
`raiseForStatus()` would then turn into a `Ja3Error` with `errorCode: 5`.)

Many URLs at once, over one session, without stopping the loop:

```js
// The pool that actually decides overlap is Node's: start with UV_THREADPOOL_SIZE=16 (or 32)
// to run that many requests at a time. ja3.maxConcurrency (256) only decides when a call
// waits for a slot instead of erroring, so leave it alone unless you are past a few hundred.
const urls = ['https://httpbin.org/delay/1', 'https://httpbin.org/delay/2', 'https://example.com/'];

const crawl = ja3.session({ impersonate: 'chrome_153', timeout: 15 });
try {
  const settled = await Promise.all(
    urls.map((url) =>
      crawl.fetch(url).then(
        (res) => ({ url, status: res.statusCode, bytes: res.bodySize }),
        // Each failure is a Ja3Error with the library's code; mapping it to a value keeps
        // Promise.all from rejecting the whole batch over one bad host.
        (error) => ({ url, error: error.codeName }),
      ),
    ),
  );

  console.log(settled);
  // [{ url: '…', status: 200, bytes: <number> }, …] — or { url: '…', error: 'REQUEST' } for
  // each host that did not answer. Nothing here threw.
} finally {
  crawl.close();
}
```

The same three URLs with `ja3.request()` would cost the sum of their latencies, and the
process would sit stopped through all of them; `Promise.all` over `fetch()` costs the longest
one. Measured against `httpbin.org/delay/1` from this machine, where one call really does
take about 2.6 s: four sequential `request()` calls 12.1 s, four concurrent `fetch()` calls
3.4 s, four concurrent `session.fetch()` calls 2.9 s.

Binary in, binary out:

```js
const fs = require('node:fs');

const icon = ja3.get('https://www.google.com/favicon.ico');
console.log(icon.bodySize, icon.header('content-type'),
  icon.body.subarray(0, 4).toString('hex'));

// A Buffer body is sent as-is; body_base64 is the same thing spelled by hand.
ja3.post('https://httpbin.org/post', fs.readFileSync('payload.bin'));
ja3.request('https://httpbin.org/post', {
  method: 'POST',
  body_base64: fs.readFileSync('payload.bin').toString('base64'),
});
```

Through a proxy, staying on HTTP/1.1, and letting a 3xx be data rather than a detour:

```js
const probe = ja3.request('https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.com%2F', {
  impersonate: 'firefox_135',
  proxy: 'http://user:pass@127.0.0.1:8888',
  force_http1: true,
  with_http3: false,
  not_follow_redirects: true,
});
// header() is case-insensitive; res.headers keeps the wire spelling, so the key here
// is 'Location', not 'location'.
console.log(probe.statusCode, probe.header('location'));
```

The proxy part of that is worth spelling out, because a proxy is where the impersonated
request stops and ordinary transport starts:

* the URL needs a scheme — `http://`, `https://`, `socks5://` or `socks5h://`.
  `127.0.0.1:8888` is refused with `errorCode: 5` and a "specify full url" message.
* userinfo in the URL becomes one `Proxy-Authorization: Basic …` header on the `CONNECT`;
  without userinfo the header is still sent, empty. A proxy that challenges you and gets
  that empty header answers 407, which surfaces as `errorCode: 5` with
  `Proxy responded with non 200 code: 407 …` — not as a 407 response you can read.
* `http://` targets go through the same `CONNECT` tunnel as `https://` ones, so the proxy
  sees `CONNECT host:80` rather than an absolute-form request line.
* what the *origin* sees stays the impersonated profile: the proxy is one hop, the
  ClientHello and headers are still the browser's.

A fingerprint built by hand instead of picked from a profile:

```js
const hand = ja3.get('https://tls.browserleaks.com/json', {
  client_data: {
    tls_version: '1.3',                                        // required
    cipher_suites: 'TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,'
      + 'TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,'
      + 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    curves: 'X25519MLKEM768:X25519:P256:P384',                 // : separated, >= 3
    signature_hashed: '0403,0804,0401',                        // hex, as a capture writes it
    http_2_setting: '1:65536;2:0;4:6291456;6:262144',
    http_2_window_update: 15663105,
    cert_compression: 'brotli',
    tls_grease: true, alps: true, ech: true, compressed: true,
    user_agent: 'HandBuilt/1.0',
  },
});
console.log(hand.json().ja3_hash, hand.json().akamai_hash, hand.json().user_agent);
```

A typo is reported rather than ignored:

```js
const t = ja3.get('https://httpbin.org/get', { impersonate: 'chrome_133', with_http4: true });
console.log(t.warnings);   // ['unknown option "with_http4" ignored']
```

## Vendoring instead of packaging

`index.js` plus `lib/native.js` is the whole binding and needs only `koffi`: copy them
into your project (from `cffi/bindings/node` in a checkout — the release archives carry the
library, its C header, the Python binding and `smoke.py`, not the JS sources) and point
`JA3_CLIENT_LIB` (or `new Ja3({ libraryPath })`) at a library you built with
`make -C cffi host`.

## Further reading

The full ABI — the six export functions, the JSON envelope, the C header — is documented
in [cffi/README.md](https://github.com/smallerqiu/ja3-client/blob/master/cffi/README.md),
and how the three packages are built and shipped is in
[PACKAGING.md](https://github.com/smallerqiu/ja3-client/blob/master/cffi/PACKAGING.md).
This file is the whole API for the common cases and does not depend on either.
