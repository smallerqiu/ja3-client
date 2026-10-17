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
co-developing with a sibling `../ja3-utls` checkout:

```
go 1.26.0

use (
	.
	../ja3-utls
)
```

Before shipping, prove the published-dependency path, which resolves `utls` from the
proxy exactly like a consumer does:

```sh
GOWORK=off go build ./...
```

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
| `https://tls.peet.ws/api/all` | `tls.ciphers`, `tls.extensions` (**in the order sent**, each entry carrying its own decoded content: `signature_algorithms`, `supported_groups`, `shared_keys`, `versions`, `protocols`, `algorithms`, and `data` as raw hex for anything peet does not know — `trust_anchors` arrives as `Unknown extension 51764`), `tls.peetprint`, `tls.ja4`, `http2.akamai_fingerprint`, `http2.sent_frames`, `tcpip` |
| `https://tls.browserleaks.com/json` | `ja3`, `ja3n_hash`, `ja4`, `http2` (SETTINGS frame order and values) |

Also grab the `sec-ch-ua`, `sec-ch-ua-version`, `user-agent` and the **header order**
from DevTools → Network → the request's headers. Those are not in the JSON above.

`/api/basic` on peet serves HTML; the JSON is `/api/all`.

Save the captures somewhere gitignored (`client_data/` is in `.gitignore`). They are
a real machine's fingerprint — IP, DNS hints, cookie-free but device-specific trust
store — and a profile is the reviewed summary of them; the raw dump is not the
repository's business.

### 3. Decide which kind of change it is

Compare the new capture with the anchor your line would inherit from (today:
`Chrome_152`, `Chrome_150`, `Chrome_136`, `Edge_136`, `Firefox_135` — see the
comments in `ja3/profiles.go` for which Chrome versions each one carries). Two outcomes:

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
"chrome_156": c(Chrome_156, Chrome_152),
```

`Client` and `Version` are labels on the `ClientHelloID` (cache key, log output),
so a `c(Chrome_156, Chrome_152)` line reports `chrome/152` internally while the
User-Agent says 156. That is the trade you are making when the bytes really are
152's. When Chrome's ClientHello itself changes, write the changed fields onto a
new full anchor block instead of reusing the old one — that is how `Chrome_150`
(the ML-DSA signature schemes) and `Chrome_152` (the `trust_anchors` extension)
came to exist next to `Chrome_136`.

### 4. Which ClientData field answers which capture

| captured from the browser | `ClientData` field | format |
| --- | --- | --- |
| cipher suites, in order | `CipherSuites` | comma-separated Go names (`TLS_AES_128_GCM_SHA256,`… ) |
| supported groups | `Curves` | colon-separated (`X25519MLKEM768:X25519:P256:P384`) |
| signature_algorithms | `SignatureHashed` | comma-separated (`ECDSAWithP256AndSHA256,PSSWithSHA256,`…); a scheme the library has no name for goes in as raw **hex** (`0904,0905,0906`, or `MLDSA44,MLDSA65,MLDSA87` — the ML-DSA codepoints Chrome 150 added, now named) |
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
| trust_anchors (0xca34 / 51764) | `TlsTrustAnchors` | bool; sends the extension with an **empty** identifier list (Chrome 152+) |
| session_ticket absent | `NoTlsSessionTicket` | bool |
| SETTINGS frame | `Http2Setting` | `1:65536;2:0;4:6291456;6:262144` (order matters) |
| WINDOW_UPDATE | `Http2WindowUpdate` | uint32 |
| priority frames string | `Http2Priorities` | peet's `m,a,s,p` list; `0` when the browser sends none |
| pseudo-header order | `Http2PseudoHeaderOrder` | 4 letters, e.g. `masp` (`m`ethod, `p`ath, `:a`uthority, `s`cheme) |
| stream WEIGHT / dependency / exclusive | `Http2StreamWight`, `Http2StreamDep`, `Http2StreamExclusive` | numbers; note the typo in `Wight`, it is the field name. `Http2StreamWight` is the **wire byte**, which is zero-indexed: Chrome's reported `weight: 256` is written as `255`. Over 255 is a hard error, not a truncation (see the deviations below). |

Anything the library cannot name fails loudly and tells you so: `don't support this
curve: …`, `don't support this certCompression: …`, `don't support this ext: …`.

`SignatureHashed` is the one field where a silent mistake is possible, because the two
id bases are mixed in this table. Unknown tokens are parsed as **hexadecimal**, so a raw
codepoint is `0904`, and the names in `signatureAlgorithms` (`MLDSA44`) resolve to the
same bytes. The fingerprint sites print those schemes in **decimal** — `2308` — and
`TlsExtensionOrder` really does want decimal, so pasting `2308` into `SignatureHashed`
is accepted without a word and puts `0x2308` on the wire. If `ja4` matches but
`akamai`/`ja3` do not and the extension set is right, look here first.

### 5. When the work belongs in the sibling module

`github.com/smallerqiu/utls` provides the cipher/curve/extension **types**. This
repository assembles a `ClientHelloSpec` out of them, so:

* a new codepoint whose content has to be *named* (a curve or cipher suite), or
  whose payload depends on the connection,

cannot be expressed here — it has to go into `utls` first, and only then into a
profile. v1.2.2 is that sequence: `MLDSA44/65/87` and `ExtensionTrustAnchors` went
into `common.go`, got tagged and pushed, and `signatureAlgorithms` switched from
`tls.SignatureScheme(0x0904)` to `tls.MLDSA44` afterwards. Once the tag is on
`origin`, bump **both** modules of this repository with the workspace turned off, so
that a sibling checkout cannot hide an unpushed commit:

```sh
GOWORK=off go get github.com/smallerqiu/utls@v1.2.2 && GOWORK=off go mod tidy
cd cffi && GOWORK=off go get github.com/smallerqiu/utls@v1.2.2 && GOWORK=off go mod tidy
```

`cffi/` is a second main module with its own `go.sum` line for `utls`, and the shipped
`.so`/`.dll`/`.dylib` is built from it — a stale `v1.2.1` there quietly releases a
library linked against the older `utls`. A new ordering of extensions that already
exist, or a changed SETTINGS list, needs no `utls` change at all.

A codepoint the library does not know but whose bytes are fixed can be sent from
this repository alone with `tls.GenericExtension{Id, Data}`, which writes the
payload verbatim — that is how `TlsTrustAnchors` emits `0xca34` with an empty
identifier list. Reach for it only when the content really is constant: a
machine-specific or shuffled payload would freeze a fingerprint that a browser
changes, and no hash above looks inside the extension anyway.

### 6. Verify, in this order

```sh
go build ./... && go test -count=1 $(go list ./... | grep -v '/tests$')
go run ./example/impersonate -impersonate chrome_152 -url https://tls.peet.ws/api/all
```

Compare the response against your capture and expect these to match: `ja3_hash`,
`ja3n_hash`, `ja4` (the hash segments), `akamai_fingerprint_hash`, the extension
**set**, the SETTINGS values. Then check the two things that will not match, and
know why before you call it done:

* **The `h3` ALPN.** Nine anchor blocks set `WithHttp3: &withHttp3` (`Chrome_132`,
  `Chrome_136`, `Chrome_137_ios`, `Chrome_150`, `Chrome_152`, `Edge_136`,
  `Opera_120`, `Brave_1_8` and the `var withHttp3 = true` they all point at), and
  `c(new, anchor)` passes it down, so the Chrome/Edge/Opera lines advertise
  `h3, h2, http/1.1` while Firefox, Safari and the rest send `h2, http/1.1`. A
  browser on a TCP connection never offers `h3` first — your Chrome 142-155
  captures all say `alpn: ["h2","http/1.1"]` — so browserleaks reads `ja4` as
  `…h3…` for a Chrome profile where a real Chrome reads `…h2…`, while tls.peet.ws
  happens to print `h2` for the same hello. Send `with_http3: false` to compare like
  for like (that is what the §6 command line above is really testing). See
  "HTTP/3 is advertised, not implemented" below for why the flag exists at all.
* **Header order and `sec-ch-ua`.** The library sets only `user-agent` plus
  whatever you pass in `Headers`; it does not synthesize a browser's header set or
  order. A profile id is not a request; if the site checks `sec-ch-ua`, that is
  your code's job.

Then read the deviations list at the bottom: no Chrome profile matches a capture's
`weight: 256` prose (the wire byte is 255), and from Chrome 152 on the built
profiles also do not match the captured leading GREASE signature scheme or the
`trust_anchors` payload — each of those has a written reason.

No network for the live compare? Check the spec offline instead:
`BuildClientHelloSpec(id, &noHttp3)`, then `ClientHelloId.SpecFactory()`, then read
every `spec.Extensions` entry as `[type:2][length:2][data]` and decode the content
you care about. Two gotchas: an extension with nothing to write reports `Len() == 0`
(`SNIExtension` before a server name exists), so guard before indexing; and the two
GREASE extension slots read as `0000` until the connection fills them in. What you
are asserting is that the **set** of ids and the decoded content equal the capture's
non-GREASE ones — that is what `ja4`'s extension count and hash segments see.
`go test ./ja3/ -run TestGoldenJA4` does exactly that for the Chrome bands, against
the hashes the captures reported; read `ja3/ja4_golden_test.go` before adding a band.

### 7. Finish the change

* add the id to the supported-browser table in `Readme.md` (and to `cffi/README.md`
  if the row there is stale — it lists the same ids);
* `DefaultImpersonate` and `DefaultClient` in `ja3/mapper_profiles.go` are a
  deliberate choice, not a chore: moving them changes what every caller who sets
  nothing gets, so do it in its own commit with its own reason;
* if the library is used through the shared library, run `cd cffi && make check`
  (it rebuilds the host library and loads it from Python and Node);
* release: bump the version in the four places the packages read it (`cffi/bindings/node/package.json`,
  `PACKAGE_VERSION` in `cffi/bindings/python/ja3_client_binaries.py`, `version` in
  `cffi/bindings/python/pyproject.toml`, `<Version>` in `cffi/bindings/csharp/Ja3Client.csproj`),
  commit, `git tag v1.2.5 && git push --tags`. `.github/workflows/release.yml` gates on
  the tests, cross-builds the matrix and attaches the archives; `packages.yml` refuses to
  run at all unless all four strings equal the tag, then publishes npm/PyPI/NuGet (see
  `cffi/PACKAGING.md`).

## Known deviations worth reading before you debug a fingerprint

* **Chrome and Edge shuffle the TLS extension order on purpose.** Chrome itself has
  randomized the ClientHello extension order since Chrome 110 (a GREASE-style
  robustness/anti-fingerprinting change), so `chrome_136` … `chrome_155` and the
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
* **tls.peet.ws's ja4 sees a padding extension on Chrome 135 and 136 that is not in
  the bytes.** Those two captures read `t13d1516h2_8daaf6152771_fca9c764716e`, while
  every 143-through-151 one (and 142 on browserleaks) reads `…_d8a2da3f94cd`, and the
  distance between the two is exactly one id: peet's `ja4_r` hashed list carries
  `0015` (padding). Its own `extensions` array, `ja3` and `peetprint` for the same
  capture all show sixteen non-GREASE extensions with no 21, so that flag is peet's,
  not Chrome's — and BoringSSL adds padding only to pull a 256-to-511-byte hello up to
  512, while every one of these captures is about 1.8 KB (recounted from the capture's
  own extension lengths: 136 and 148 are both 1768 bytes, and only the 136 one carries
  the flag, so the length rule cannot be what separates them).
  `Chrome_136` therefore keeps `TlsPadding: false` and `chrome_136` … `chrome_149`
  stay one band. `TestPaddingIsTheOnlyChrome136Delta` holds the arithmetic: switch
  padding on and the built profile answers the capture's own hash, which is what shows
  nothing else about the two differs.
* **Chrome 152+ opens `signature_algorithms` with a GREASE scheme we cannot pin.**
  The captures for Chrome 152/153/154/155 (2026-10-15/16) start that list with
  `0x8aaa`, `0x6a6a`, `0x1a1a`, `0xeaea` — a fresh random value per connection.
  `Chrome_150` and `Chrome_152` therefore start at `0904,0905,0906` (the ML-DSA
  codepoints, the part that is actually stable) and send no leading GREASE scheme.
  This does not cost you `ja4`: ja4 drops GREASE values before hashing signature
  algorithms, and that was measured rather than assumed — `chrome_152` through the
  library answers `t13d1517h2_8daaf6152771_cb7bf5808d99`, the capture's own ja4,
  with all eleven schemes and no GREASE. It does cost you `peetprint`, which keeps
  the GREASE entry (`2308-2309-…` where the browser prints
  `GREASE-2308-2309-…`) and so differs run
  to run for a real Chrome no matter what. Chrome 150 and 151 are the two captures
  that show this is a 152 change and not a 150 one: their list opens straight on
  `mldsa44`, with no GREASE in front.
* **`trust_anchors` goes out empty.** Chrome 152+ always offers extension `0xca34`;
  what is inside depends on the machine. The captured host sent 28 identifier hints
  (an `0x00b8`-length list whose order even shuffled between runs), while a browser
  with no HTTPS DNS hint on the origin sends an empty list — the shape
  `TlsTrustAnchors` reproduces (`Data: {0x00, 0x00}`, extension length 2). Nothing
  above hashes extension *content*, so `ja4` and `peetprint` match either way — the
  built `chrome_152` is seen as `Unknown extension 51764` among 17 non-GREASE
  extensions, and as `…-51-51764-65037-65281-…` in the peetprint extension list.
  Only a site that reads the payload would notice, and it would have to be reading
  someone else's trust store to care.
* **Chrome 154-style `pre_shared_key` (`0x29`) is not a profile field.** That
  capture's `t13d1518h2_…` has one extension more than 152/153/155 because the
  browser was resuming a session. A first connection from a real Chrome has no
  `0x29` either, which is what these profiles send; do not "add" it to chase a
  1518 hash. Measured: `chrome_154` answers `t13d1517h2_8daaf6152771_cb7bf5808d99`
  — 152's extension count, 152's, 153's and 155's hash — because the bytes really
  are theirs.
* **`Http2StreamWight` is the wire byte, not the browser-reported weight.**
  `generate.go` writes `uint8(config.Http2StreamWight)` and HTTP/2 weights are
  zero-indexed on the wire, so Chrome's captured `weight: 256` is the byte `255`.
  Every anchor used to read this backwards — Chrome, Edge, Opera, Brave, QQ, QH360,
  UC, Samsung, Xiaomi and four Safari blocks all said `256`, which truncated to `0`,
  i.e. the lightest stream in HTTP/2 — until 2026-10-15. Values above 255 are now
  rejected with `http2StreamWight … does not fit the priority weight byte` instead
  of silently truncating, so write the byte (255), not the prose (256). The
  `akamai_fingerprint` string never contained it, so the hash stayed green the whole
  time; only `http2.sent_frames` showed the wrong byte.
* **Safari 26.5 sends no priority in HEADERS at all** (`mac_26.5.json`, flags are
  `EndStream|EndHeaders`). The Safari anchors set a weight, and
  `PriorityParam.IsZero()` only skips the priority field when *every* part is zero,
  so `FlagHeadersPriority` goes out. Same category as the point above: visible in
  `sent_frames`, invisible to the akamai string.
* **HTTP/3 is advertised, not impersonated.** `roundtripper.go:145` always dials
  TCP, the transport is then chosen from the negotiated ALPN (`:188`), and real
  servers answer `h2` — so the `h3` in a Chrome profile's ALPN is only a claim. If a
  server ever does negotiate `h3` over TCP, `roundtripper.go:265-315` builds an
  `http3.Transport` from a `tls.Config` that carries **no `ClientHelloID`** and then
  dials a fresh UDP connection: the handshake is the library's own Go/utls hello,
  not the browser you asked for, and the profile's proxy and `disableIPV4/6` do not
  follow it (the `network == "tcp"` guard at `:141`). Nothing reads `Alt-Svc`, so an
  h3 upgrade is never followed either. Before anyone "makes HTTP/3 work", the
  missing piece is a `ClientHelloID`-aware QUIC dialer.
* A typo in `impersonate` is not an error: `BuildClientHelloSpec` logs
  `the input client … don't support, so use default` and falls back to
  `DefaultClient`. Check the log or `WithDebug` when a capture disagrees.
* **`Headers` forces `accept-encoding: identity`.** `session.go:88-93` overwrites
  the value whenever a request carries headers at all (even one the caller set),
  while `cffi/sessions.go:63-80` pins it only *unless the caller chose it*. The
  reason is real but narrower than the code: on HTTP/2 this fork decompresses
  whatever comes back (`http/h2_bundle.go:9275-9277` calls `DecompressBody`
  regardless of who asked; gzip/br/deflate/zstd readers exist at
  `http/transport.go:2873-2983`), on HTTP/1 only when the caller's header says gzip
  (`http/transport.go:2569-2572` widens the stock rule), and on HTTP/3 the stock
  gzip-only rule again (`http3/stream.go:286-288`). So `br`/`deflate`/`zstd` over
  HTTP/1 arrive as compressed bytes that the FFI can only return as base64 — which
  is what the blanket `identity` is protecting.
* Multi-value headers are joined with `", "` into one value, and Go's `http.Header`
  is a map: HTTP/1.1 header order is not controllable from this API.

## Issue templates

`.github/ISSUE_TEMPLATE/` has three forms (bug, fingerprint mismatch, new browser
version) and blank issues are off. The mismatch and new-version forms ask for the
captures above — that is the data this section produces.
