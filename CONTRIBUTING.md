# Contributing

Everything here is written for the job people actually come here to do: **add a
browser version whose bytes are right**. The Go API is documented in
[Readme.md](Readme.md); the C ABI and the Node/Python/C# bindings live in
[cffi/README.md](cffi/README.md).

## Setting up

```sh
go build ./...                                   # root module
go test -count=1 $(go list ./... | grep -v '/tests$')
cd cffi && make check                            # library + every binding, offline
```

`cffi/` is its own main module with `replace github.com/smallerqiu/ja3-client => ../`,
so the shipped `.so`/`.dll`/`.dylib` always contains the code you just tested. Do not
add a `replace` to the root `go.mod` — consumers would silently resolve a different
`utls` (CI checks this). The repository's `go.work` is gitignored and only for
co-developing with a sibling `../ja3-utls` checkout.

`tests/` is excluded from CI on purpose: it hits `tls.peet.ws`,
`tls.browserleaks.com` and a local proxy at `127.0.0.1:7890`. Run it by hand on
release day.

## Adding a browser version

### 1. Get that exact browser, even if you do not have it

Chrome publishes every version as **Chrome for Testing**, so "my machine is on 141"
never means you cannot capture 156:

```sh
curl -s https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json \
  | python3 -c "import json,sys; [print(f'{c:8} {v[\"version\"]}') for c,v in json.load(sys.stdin)['channels'].items()]"
```

Measured 2026-10-15: Stable `155.0.8059.79`, Beta `156.0.8078.12`, Dev `157.0.8081.0`,
Canary `158.0.8105.0`. For a specific build, download from
`https://storage.googleapis.com/chrome-for-testing-public/<full-version>/<platform>/chrome-<platform>.zip`
(`<platform>` = `linux64|mac-x64|mac-arm64|win32|win64`, full version including the
build, e.g. `156.0.8078.12`), and run it with a throwaway profile:

```sh
./chrome-mac-arm64/Google\ Chrome\ for\ Testing.app/Contents/MacOS/Google\ Chrome\ for\ Testing \
  --user-data-dir=/tmp/cft-156 --no-first-run --incognito
```

No extensions, no sync, nothing signed in. Then open the capture endpoints below
in that window.

### 2. Capture from two endpoints, because they do not tell you the same things

| endpoint | what to read off it |
| --- | --- |
| `https://tls.peet.ws/api/all` | `tls.ciphers`, `tls.extensions` (**in the order sent**), `tls.signature_algorithms`, `tls.supported_groups`, `tls.alpn`, `tls.cert_compression_algorithms`, `http2.akamai_fingerprint`, `http2.sent_frames`, `tcpip` |
| `https://tls.browserleaks.com/json` | `ja3`, `ja3n_hash`, `ja4`, `http2` (SETTINGS frame order and values) |

Also grab the `sec-ch-ua`, `sec-ch-ua-version`, `user-agent` and the **header order**
from DevTools → Network → the request's headers. Those are not in the JSON above.

`/api/basic` on peet serves HTML; the JSON is `/api/all`.

### 3. Decide which kind of change it is

Compare the new capture with the anchor your line would inherit from (today:
`Chrome_136`, `Edge_136`, `Firefox_135`). Two outcomes:

* **Only the version string moved.** The extension list, cipher list, groups,
  signature algorithms, ALPN and the HTTP/2 SETTINGS/window-update/priorities are
  unchanged. Then this is a two-line change, and you do not touch the spec.

* **The bytes changed.** A new extension, a new key-share group, a reordered
  extension list, a different SETTINGS pair. Then the anchor's own fields have to
  change, or you add a new anchor. Do not "just add the UA" and call the profile
  Chrome 156 — the file would be lying, and the first person comparing against a
  real 156 will file it as a fingerprint mismatch, correctly.

A profile is two pieces of code, nothing else:

```go
// ja3/profiles.go — only the fields that differ from the anchor are needed
var Chrome_156 = ClientData{
    UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
}

// ja3/mapper_profiles.go — `c(new, anchor)` = the anchor's bytes with the new UA
"chrome_156": c(Chrome_156, Chrome_136),
```

`Client` and `Version` are labels on the `ClientHelloID` (cache key, log output),
so a `c(Chrome_156, Chrome_136)` line reports `chrome/136` internally while the
User-Agent says 156. That is the trade you are making when the bytes really are
136's. When Chrome's ClientHello itself changes, write the changed fields onto a
new full anchor block instead of reusing the old one.

### 4. Which ClientData field answers which capture

| captured from the browser | `ClientData` field | format |
| --- | --- | --- |
| cipher suites, in order | `CipherSuites` | comma-separated Go names (`TLS_AES_128_GCM_SHA256,`… ) |
| supported groups | `Curves` | colon-separated (`X25519MLKEM768:X25519:P256:P384`) |
| signature_algorithms | `SignatureHashed` | comma-separated (`ECDSAWithP256AndSHA256,PSSWithSHA256,`…) |
| TLS extension order | `TlsExtensionOrder` | **decimal ids, `-`-separated** (`0-23-65281-10-11-35-16-5-…`) |
| supported_versions | `TlsVersion` | `"1.3"` |
| key_share entries | `TlsKeySharesLimit` | int (default 3) |
| GREASE | `TlsGrease` | bool |
| padding extension | `TlsPadding` | bool |
| encrypted_client_hello | `Ech` | bool (boringssl codepoint) |
| compress_certificate | `CertCompression` | `brotli` / `zlib` / `zstd`, comma-separated |
| application_settings (new / old) | `ALPS` / `ALPSO` | bool |
| ALPN forced to h1+h2 | `ALPSS` | bool |
| delegated_credentials | `TlsDelegatedCredentials` | comma-separated schemes |
| record_size_limit | `TlsRecordSizeLimit` | int |
| session_ticket absent | `NoTlsSessionTicket` | bool |
| SETTINGS frame | `Http2Setting` | `1:65536;2:0;4:6291456;6:262144` (order matters) |
| WINDOW_UPDATE | `Http2WindowUpdate` | uint32 |
| priority frames string | `Http2Priorities` | peet's `m,a,s,p` list; `0` when the browser sends none |
| pseudo-header order | `Http2PseudoHeaderOrder` | 4 letters, e.g. `masp` (`m`ethod, `p`ath, `:a`uthority, `s`cheme) |
| stream WEIGHT / dependency / exclusive | `Http2StreamWight`, `Http2StreamDep`, `Http2StreamExclusive` | numbers; note the typo in `Wight`, it is the field name |

Anything the library cannot name fails loudly and tells you so: `don't support this
curve: …`, `don't support this certCompression: …`, `don't support this ext: …`.

### 5. When the work belongs in the sibling module

`github.com/smallerqiu/utls` provides the cipher/curve/extension **types**. This
repository assembles a `ClientHelloSpec` out of them, so:

* a new codepoint with real content (a new extension Chrome started sending),
* a new named curve or cipher suite,

cannot be expressed here — add it in `utls`, release it, bump the `require` in
`go.mod`, and then write the profile. A new ordering of extensions that already
exist, or a changed SETTINGS list, needs no `utls` change at all.

### 6. Verify, in this order

```sh
go build ./... && go test -count=1 $(go list ./... | grep -v '/tests$')
go run ./example/impersonate -impersonate chrome_156 -url https://tls.peet.ws/api/all
```

Compare the response against your capture and expect these to match: `ja3_hash`,
`ja3n_hash`, `ja4` (the hash segments), `akamai_fingerprint_hash`, the extension
**set**, the SETTINGS values. Then check the two things that will not match, and
know why before you call it done:

* **The `h3` ALPN.** `ja3/profiles.go` sets `var withHttp3 = true`, so every
  profile advertises `h3` first. browserleaks reads `ja4` as `…h3…` where a real
  Chrome reads `…h2…`; tls.peet.ws happens to print `h2` for the same hello. Send
  `with_http3: false` to compare like for like.
* **Header order and `sec-ch-ua`.** The library sets only `user-agent` plus
  whatever you pass in `Headers`; it does not synthesize a browser's header set or
  order. A profile id is not a request; if the site checks `sec-ch-ua`, that is
  your code's job.

### 7. Finish the change

* add the id to the supported-browser table in `Readme.md` (and to `cffi/README.md`
  if the row there is stale — it lists the same ids);
* `DefaultImpersonate` and `DefaultClient` in `ja3/mapper_profiles.go` are a
  deliberate choice, not a chore: moving them changes what every caller who sets
  nothing gets, so do it in its own commit with its own reason;
* if the library is used through the shared library, run `cd cffi && make check`
  (it rebuilds the host library and loads it from Python and Node);
* release: commit, `git tag v1.2.5 && git push --tags` — `.github/workflows/release.yml`
  gates on the tests, cross-builds the matrix and attaches the archives.

## Known deviations worth reading before you debug a fingerprint

* **Chrome and Edge shuffle the TLS extension order on purpose.** Chrome itself has
  randomized the ClientHello extension order since Chrome 110 (a GREASE-style
  robustness/anti-fingerprinting change), so `chrome_136` … `chrome_141` and the
  Edge anchors setting `RandomExtensionOrder: true` is fidelity, not a bug — Safari
  and Firefox keep a fixed order, which is why their anchors pin
  `TlsExtensionOrder` instead. Measured 2026-10-15 through the built library:
  `chrome_141` differs run to run, `firefox_135` and `safari_18_0` do not. The
  consequence for debugging: a raw JA3 (order-sensitive) from a Chrome profile will
  not repeat, exactly as it does not for a real Chrome, while `ja4` and `peetprint`
  hash a sorted extension list and stay stable. Do not "fix" a Chrome profile by
  pinning an order. One exception: `chrome_99_android` shuffles too, and Chrome 99
  predates the 110 change.
* **`random_extension_order` / `RandomExtensionOrder` is opt-in only.** A request
  can turn shuffling *on* for a fixed-order profile, but cannot turn it *off* for a
  Chrome/Edge profile: `session.go` appends `WithRandomTLSExtensionOrder()` when the
  field is true, and `roundtripper.go` then reads `ClientHelloID.RandomExtensionOrder`
  from the profile regardless. For a deterministic Chrome order, pass your own
  `ClientData` (`RandomExtensionOrder: false` plus `TlsExtensionOrder`) instead of
  `Impersonate`. Pinning `TlsExtensionOrder` alone does nothing while the flag is
  set — `Firefox_132` does exactly that, so its pinned order is never sent, and
  real Firefox has a fixed order.
* A typo in `impersonate` is not an error: `BuildClientHelloSpec` logs
  `the input client … don't support, so use default` and falls back to
  `DefaultClient`. Check the log or `WithDebug` when a capture disagrees.
* Passing `Headers` forces `accept-encoding: identity` afterwards, so a caller
  cannot ask for compression while setting headers.
* Multi-value headers are joined with `", "` into one value, and Go's `http.Header`
  is a map: HTTP/1.1 header order is not controllable from this API.

## Issue templates

`.github/ISSUE_TEMPLATE/` has three forms (bug, fingerprint mismatch, new browser
version) and blank issues are off. The mismatch and new-version forms ask for the
captures above — that is the data this section produces.
