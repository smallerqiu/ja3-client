# ja3-client (C#)

Browser TLS/HTTP2/HTTP3 fingerprint impersonation from .NET. The handshake is the part
that gets you blocked — the ClientHello's cipher order, extensions and ALPN list, plus
the HTTP/2 `SETTINGS` frame and the pseudo-header order — and those are not headers, so
no amount of `User-Agent` faking changes them. This package drives a Go library
(`libja3-client`) that replays a captured Chrome / Firefox / Safari profile, through
P-Invoke. One source file, no package dependencies, and the native library is fetched
for your OS/CPU at build time.

```csharp
using Ja3Client;
using System.Text.Json.Nodes;

using var ja3 = new Ja3();
var response = ja3.Get("https://tls.browserleaks.com/json",
    new RequestOptions { Impersonate = "chrome_153" });

Console.WriteLine(response.Json<JsonObject>()!["ja3n_hash"]);   // what the site read from your TLS
```

`dotnet add package ja3-client` needs .NET 8 or newer and adds no other package.

## What you can call

| call | returns | |
| --- | --- | --- |
| `new Ja3(string? libraryPath = null)` | `Ja3` | loads the library; refuses an ABI it was not written against (`Ja3.AbiVersion`) |
| `ja3.Request(url, options)` | `Response` | one-shot request: builds a client, uses it once, drops idle connections |
| `ja3.Get(url, options)` | `Response` | `Request` with `Method = "GET"` |
| `ja3.Post(url, string? body = null, options)` | `Response` | `Request` with `Method = "POST"`; for bytes use `options.BodyBase64` |
| `ja3.OpenSession(SessionOptions? options = null)` | `Session` | a client that keeps its connection pool and cookie jar; `IDisposable` |
| `ja3.LibraryPath` | `string` | the library file actually loaded |
| `ja3.SdkVersion` | `string` | version stamped into the library at build time |
| `ja3.BuildTime` | `string` | when that library was built (UTC, RFC 3339) |
| `ja3.Dispose()` | | for symmetry with the other bindings; .NET holds no handle to release. Dispose your sessions. |

## Options

`SessionOptions` holds the client-level fields, `RequestOptions : SessionOptions` adds
the per-call ones. The C# names are the properties; the wire names are the `snake_case`
keys the ABI documents, and the serializer emits those, so a payload built by hand with
`JsonSerializer` — or a name copied from another language's docs — speaks the same
language. Unknown keys are never dropped: the library reports them in
`response.Warnings`. An option left at `null` is omitted, which is how a tri-state field
keeps its default.

Client-level — only read while the client is being built, i.e. by `Request()` and
`OpenSession()`; on a session request the library has already built the client and ignores
them:

| property | JSON key | type | default | meaning |
| --- | --- | --- | --- | --- |
| `Impersonate` | `impersonate` | string | `chrome_141` | profile id: `chrome_133`, `chrome_153`, `firefox_135`, `safari_170`, … |
| `Ja3` | `ja3` | string | | raw JA3 string; wins over `Impersonate` |
| `Akamai` | `akamai` | string | | Akamai HTTP/2 settings string, used together with `ja3` |
| `ClientData` | `client_data` | `JsonNode` | | hand-built fingerprint (see below); wins over `ja3` |
| `Proxy` | `proxy` | string | | scheme required: `http://user:pass@host:port`, `https://host:port`, `socks5://host:port` (`socks5h` too). A missing scheme throws `Ja3Exception` with `Code: Request`, not a silent no-proxy. |
| `SourceIp` | `source_ip` | string | | local address to bind |
| `Timeout` | `timeout` | int | 30 | seconds; `0` keeps the library default |
| `ForceHttp1` | `force_http1` | bool | false | never negotiate HTTP/2 |
| `WithHttp3` | `with_http3` | bool? | profile default | `null` keeps the profile's choice, `false` removes `h3` from ALPN — see [HTTP/3](#http3) |
| `RandomExtensionOrder` | `random_extension_order` | bool | false | shuffle the TLS extension order |
| `NotFollowRedirects` | `not_follow_redirects` | bool | false | stop at a 3xx instead of following it |
| `WithDebug` | `with_debug` | bool | false | library debug logging to stderr |
| `Headers` | `headers` | `Dictionary<string, JsonNode?>` | | default headers for every request on this client/session |

Per-call, on `RequestOptions`:

| property | JSON key | type | meaning |
| --- | --- | --- | --- |
| `Url` | `url` | string | filled in for you by `Request`/`Get`/`Post`; an empty one throws `Ja3Exception` with `Code: NilArgument` |
| `Method` | `method` | string | default `GET` |
| `Headers` | `headers` | `Dictionary<string, JsonNode?>` | `"value"`, a `JsonArray` of values (one header line per element — an echo site usually shows them comma-joined), or `null` to **remove** a header the session would otherwise send |
| `Body` | `body` | string | UTF-8 text body |
| `BodyBase64` | `body_base64` | string | binary body; wins over `Body` |
| `Timeout` | `timeout` | int | per-call override of the client timeout |
| `WithDebug` | `with_debug` | bool | |

One C# quirk to know: `Request`/`Get`/`Post` write `Url`, `Method` and `Body` into the
options object you hand them, so reuse one `RequestOptions` across calls and each call
overwrites the previous target. Build a fresh object per request — or keep the
`SessionOptions` you opened the session with, which is never mutated.

Per-call `Headers` are merged **over** the client's `Headers`, not instead of them — and
that merge is what keeps the profile's `user-agent` alive when you add one header of your
own. Two defaults the library installs for you, because the response is unreadable
without them:

* `user-agent` taken from the chosen profile.
* `accept-encoding: identity`. The transport does not decompress, so a negotiated `br`
  or `gzip` body would arrive as base64 you cannot read. Set `accept-encoding` yourself
  (or remove it with `Headers = { ["accept-encoding"] = null }`) when you want to handle
  compression, and read `Response.Body` plus the `content-encoding` header in that case.

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
| `tls_version` | `any`, `1.3`, `1.2` or `1.1` | required — an empty one is `Code: Request` with `ja3Str tls version error` |

## Response

Every call returns a `Response`, a decoded view of one JSON envelope. Reading a property
never touches the library again; the envelope stays whole in `response.Raw`.

| member | type | |
| --- | --- | --- |
| `StatusCode` | `int` | HTTP status; `0` if the envelope had none |
| `Protocol` | `string` | `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0` |
| `Headers` | `IReadOnlyDictionary<string, string[]>` | repeated headers stay a list, original casing |
| `SetCookies` | `IReadOnlyList<string>` | raw `Set-Cookie` values, in order — a login flow needs the attributes and the sequence, which a map loses |
| `Warnings` | `IReadOnlyList<string>` | unknown options, ignored `client_data` keys |
| `Body` | `byte[]` | decoded from `body_base64` when the body was binary |
| `BodySize` | `int` | bytes |
| `Session` | `ulong` | the handle that made this request, `0` for one-shot calls |
| `Raw` | `Envelope` | the parsed envelope, keys and all — see the mapping below |
| `Text` | `string` property | body decoded as UTF-8 |
| `Json<T>()` | `T?` | `JsonSerializer.Deserialize<T>(Text)` — `Json<JsonObject>()`, `Json<MyDto>()`, `Json<List<Item>>()` |
| `Header(name)` | `string?` | first value, case-insensitive |
| `IsOk` | `bool` property | `200 <= StatusCode < 400`. Note this is **not** the envelope's `ok`, which means "the call worked"; an HTTP 404 is a successful call. |
| `RaiseForStatus()` | `Response` | throws `Ja3Exception` (`Code: Request`) unless `IsOk` |

A non-zero `error_code` throws instead of returning anything, so a `Response` in your
hands always means the transport succeeded.

`response.Raw` is the envelope exactly as the ABI defines it, and its properties carry
those keys: `error_code` → `ErrorCode`, `error` → `Error`, `ok` → `Ok`, `status_code` →
`StatusCode`, `protocol` → `Protocol`, `headers` → `Headers`, `set_cookies` → `SetCookies`,
`body` → `Body`, `body_base64` → `BodyBase64`, `body_binary` → `BodyBinary`, `body_size` →
`BodySize`, `warnings` → `Warnings`, `session` → `Session`, plus `version` → `Version`,
`abi` → `Abi` and `build_time` → `BuildTime`, which only the version call fills.
`BodyBinary` is the library saying "the body only exists as base64", which `Response.Body`
already decoded for you.

## Sessions

`OpenSession()` builds one client and keeps it: connection pool, cookie jar, default
headers, profile. Requests on it reuse that state, which is the difference between one
page load and a login flow.

```csharp
using var session = ja3.OpenSession(new SessionOptions { Impersonate = "chrome_133", Timeout = 20 });

session.Get("https://example.com/");          // sets a cookie
session.Get("https://example.com/account");   // sends it back, over the same connection

Console.WriteLine($"{session.Handle} {session.IsClosed}");   // 14041280 False

session.Dispose();

try
{
    session.Get("https://example.com/");      // the handle is gone
}
catch (Ja3Exception error)
{
    Console.WriteLine(error.Code);            // InvalidHandle
}
```

| member | |
| --- | --- |
| `Request(url, RequestOptions?)`, `Get(url, RequestOptions?)`, `Post(url, string? body, RequestOptions?)` | same per-call properties as `RequestOptions` |
| `Close()` | the same as `Dispose()`, which `using` calls for you; idempotent |

Requests are safe from any thread — the Go client pools connections and guards its cookie
jar — but a handle you have closed is not: it reports `error_code: 4` (`INVALID_HANDLE`)
rather than crashing the process.

## Errors

Everything throws `Ja3Exception`, carrying the library's own code and the envelope it came
back with:

```csharp
using Ja3Client;

try
{
    ja3.Request("", new RequestOptions { Impersonate = "chrome_133" });   // empty url
}
catch (Ja3Exception error)
{
    Console.WriteLine($"{error.Code} {error.Message}");     // NilArgument ...
    Console.WriteLine(error.Envelope?.Error);               // library's own text
}
```

| `Code` (`Ja3ErrorCode`) | `error_code` | name in the envelope | when |
| --- | --- | --- | --- |
| `Ok` | 0 | `OK` | never throws; check `StatusCode` for the HTTP result |
| `NilArgument` | 1 | `NIL_ARGUMENT` | missing payload, empty `url`, null pointer |
| `BadJson` | 2 | `BAD_JSON` | a field has the wrong type, or `body_base64` is not base64 |
| `SessionInit` | 3 | `SESSION_INIT` | the client could not be built (bad proxy URL, a profile that errors) |
| `InvalidHandle` | 4 | `INVALID_HANDLE` | the session id is 0, closed, or never opened |
| `Request` | 5 | `REQUEST` | transport or request-construction failure; also what `RaiseForStatus()` throws |
| `ReadBody` | 6 | `READ_BODY` | the response arrived but its body could not be read |
| `Marshal` | 7 | `MARSHAL` | the envelope itself failed — should not happen |
| `Panic` | 8 | `PANIC` | a Go panic was recovered so it could not abort your process |

Two of those depend on which call you made, because a one-shot builds the client inside the
request while a session has already built it: a bad `BodyBase64` is `BadJson` on a session
request but `Request` on a one-shot, and a proxy URL the parser rejects is `SessionInit`
from `OpenSession()` but `Request` from `Request()`.

The status is separate data: `RaiseForStatus()` exists for when you want a 404 to be an
exception too.

## HTTP/3

Some profiles advertise `h3` in their ALPN list and some do not — the Chrome, Edge, Opera
and Brave anchors do (`h3, h2, http/1.1`), Firefox and Safari do not (`h2, http/1.1`). Two
things follow, and both surprise people:

* Fingerprint sites disagree about what to report. browserleaks reads the **first** ALPN
  entry and shows `ja4` as `t13d1516h3` for `chrome_141`, while tls.peet.ws reports
  `t13d1516h2` for the same ClientHello. `WithHttp3 = false` puts browserleaks back to
  `h2`, which is what you want when comparing against a browser capture.
* When a server answers `h3` over TCP ALPN, the client opens a separate QUIC connection
  whose ClientHello is the library's own, **not** the browser you asked to impersonate.
  Treat HTTP/3 as advertised, not impersonated; some hosts also end up as `error_code: 5`
  with an `H3 error` or a timeout.

Leave the default alone otherwise. At around a million concurrent requests against
Cloudflare-fronted sites, the same Chrome profile with `h3` removed drew clearly more
challenges and errors than with it on.

## Where the library comes from

The NuGet package ships binding code plus `build/ja3-client.targets`, which MSBuild imports
automatically. On the next build that target works out this machine's `<os>-<arch>` slug,
downloads `ja3-client-<version>-<os>-<arch>.zip` from this repository's GitHub Release for
the package version, checks it against that release's `SHA256SUMS.txt`, unpacks the library
into the cache the npm and PyPI packages share, and copies it next to your executable —
which is the first place `Ja3.cs` looks, so `dotnet run` and `dotnet test` need no
environment variables:

```
~/.cache/ja3-client/<version>/<os>-<arch>/    (macOS: ~/Library/Caches, Windows: %LOCALAPPDATA%)
```

A fetch that fails is a warning, not a build error, so that a re-uploaded release cannot
break every consumer's build; set `Ja3ClientStrictFetch=true` if you would rather it did.

```sh
dotnet build -p:Ja3ClientVersion=1.2.5          # fetch a different library version
dotnet build -p:Ja3ClientOffline=true           # never touch the network
dotnet build -p:Ja3ClientSkipNativeFetch=true   # you ship your own library
dotnet publish                                  # the library goes to the publish dir too
```

At runtime the binding looks for, in order: the `libraryPath` you passed to `new Ja3()`,
`JA3_CLIENT_LIB`, the output directory and `runtimes/`, the current directory, `cffi/build`
in a checkout of this repository, and any version in the shared cache.

A load that fails is a .NET `DllNotFoundException`, not a `Ja3Exception` — and its message
names the library as `ja3-client` rather than the path it tried, so when you see one check
`JA3_CLIENT_LIB` and the file's architecture before anything else. The path actually loaded
is `ja3.LibraryPath` once the constructor returns.

## Knobs

MSBuild properties above, and the same environment variables as the other bindings:

| variable | effect |
| --- | --- |
| `JA3_CLIENT_LIB` | use this exact file; disables the target and the search |
| `JA3_CLIENT_CACHE_DIR` | move the cache (also how you point CI at a mirror) |
| `JA3_CLIENT_VERSION` | library version to fetch, overriding the package version |
| `JA3_CLIENT_BASE_URL` | download root, for a mirror or an offline test server |
| `JA3_CLIENT_REPO` | `owner/repo` if you build the library from a fork |
| `JA3_CLIENT_OFFLINE=1\|true` | never touch the network; fail with the manual recipe |
| `JA3_CLIENT_STRICT=1\|true` | make a failed fetch fatal |

## No network, no GitHub

Build it and pin it:

```sh
git clone https://github.com/smallerqiu/ja3-client && cd ja3-client/cffi && make host
export JA3_CLIENT_LIB="$PWD/build/darwin/ja3_client_arm64.dylib"   # linux: libja3_client_amd64.so
```

or unzip a release archive and point `JA3_CLIENT_LIB` at the file inside — every archive
carries `smoke.py`, which proves the download offline. Linux archives are built against
glibc (Debian bookworm); on musl (Alpine) build the library yourself, and there is no
archive for 32-bit ARM Windows.

## Recipes

Fingerprint, and what the site actually saw:

```csharp
using System.Text.Json.Nodes;

var seen = ja3.Get("https://tls.browserleaks.com/json",
    new RequestOptions { Impersonate = "chrome_153" }).Json<JsonObject>()!;
Console.WriteLine($"{seen["ja3n_hash"]} {seen["akamai_hash"]} {seen["ja4"]}");
// The keys that site answers with: user_agent, ja4, ja4_r, ja4_o, ja4_ro, ja3_hash,
// ja3_text, ja3n_hash, ja3n_text, akamai_hash, akamai_text.
```

Typed deserialization:

```csharp
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

var echo = ja3.Get("https://httpbin.org/get", new RequestOptions { Impersonate = "chrome_133" })
    .Json<Dictionary<string, JsonNode>>()!;
Console.WriteLine(echo["url"].ToString());                       // keys as the JSON spells them
Console.WriteLine(echo["headers"]["User-Agent"].ToString());

// A DTO works too, but Json<T>() uses the default serializer options, which are
// case-sensitive: name the properties the way the wire does.
record Fingerprint([property: JsonPropertyName("ja3n_hash")] string Ja3nHash,
                   [property: JsonPropertyName("akamai_hash")] string AkamaiHash);
```

POST JSON, keeping the profile's own headers:

```csharp
var posted = ja3.Post("https://httpbin.org/post", """{"q": "中文", "page": 1}""",
    new RequestOptions
    {
        Impersonate = "chrome_133",
        Headers = new Dictionary<string, JsonNode?> { ["content-type"] = "application/json" },
    });
```

Login flow: cookies and keep-alive across requests.

```csharp
using var session = ja3.OpenSession(new SessionOptions
{
    Impersonate = "chrome_133",
    Headers = new Dictionary<string, JsonNode?> { ["x-app"] = "demo" },
});

session.Get("https://httpbin.org/cookies/set?name=value");      // 302, then /cookies
var cookies = session.Get("https://httpbin.org/cookies");       // same jar, same connection
Console.WriteLine(cookies.Json<JsonObject>()!["cookies"]);      // {"name": "value"}

// Per-call headers merge over the session's, so x-app is still on this request.
var authed = session.Get("https://httpbin.org/basic-auth/u/p",
    new RequestOptions { Headers = new Dictionary<string, JsonNode?> { ["authorization"] = "Basic dTpw" } });
Console.WriteLine($"{authed.StatusCode} {authed.Json<JsonObject>()!["authenticated"]}");   // 200 true
```

(httpbin's `/basic-auth` only answers `GET`; a `POST` to it is a 405 from the server, which
`RaiseForStatus()` would then turn into a `Ja3Exception` with `Code: Request`.)

Binary in, binary out:

```csharp
var icon = ja3.Get("https://www.google.com/favicon.ico");
Console.WriteLine($"{icon.BodySize} {icon.Header("content-type")} {Convert.ToHexString(icon.Body[..4])}");

ja3.Request("https://httpbin.org/post", new RequestOptions
{
    Method = "POST",
    BodyBase64 = Convert.ToBase64String(File.ReadAllBytes("payload.bin")),
});
```

Through a proxy, staying on HTTP/1.1, and letting a 3xx be data rather than a detour:

```csharp
var probe = ja3.Request("https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.com%2F", new RequestOptions
{
    Impersonate = "firefox_135",
    Proxy = "http://user:pass@127.0.0.1:8888",
    ForceHttp1 = true,
    WithHttp3 = false,
    NotFollowRedirects = true,
});
// Header() is case-insensitive; Headers keeps the wire spelling, so the key is
// "Location", not "location".
Console.WriteLine($"{probe.StatusCode} {probe.Header("location")}");
```

The proxy part of that is worth spelling out, because a proxy is where the impersonated
request stops and ordinary transport starts:

* the URL needs a scheme — `http://`, `https://`, `socks5://` or `socks5h://`.
  `127.0.0.1:8888` throws `Code: Request` with a "specify full url" message.
* userinfo in the URL becomes one `Proxy-Authorization: Basic …` header on the `CONNECT`;
  without userinfo the header is still sent, empty. A proxy that challenges you and gets
  that empty header answers 407, which surfaces as `Code: Request` with
  `Proxy responded with non 200 code: 407 …` — not as a 407 response you can read.
* `http://` targets go through the same `CONNECT` tunnel as `https://` ones, so the proxy
  sees `CONNECT host:80` rather than an absolute-form request line.
* what the *origin* sees stays the impersonated profile: the proxy is one hop, the
  ClientHello and headers are still the browser's.

A fingerprint built by hand instead of picked from a profile — and a key the library does
not know is reported, not dropped. The typed options cannot carry a misspelled field (the
compiler is that gate), but `ClientData` is a `JsonNode` you build:

```csharp
var hand = ja3.Get("https://tls.browserleaks.com/json", new RequestOptions
{
    // Raw string literals are literal text: a JSON string value must stay on one line.
    ClientData = JsonNode.Parse("""
    {
      "tls_version": "1.3",
      "cipher_suites": "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "curves": "X25519MLKEM768:X25519:P256:P384",
      "signature_hashed": "0403,0804,0401",
      "http_2_setting": "1:65536;2:0;4:6291456;6:262144",
      "http_2_window_update": 15663105,
      "cert_compression": "brotli",
      "tls_grease": true, "alps": true, "ech": true, "compressed": true,
      "user_agent": "HandBuilt/1.0",
      "not_a_real_option": "typo"
    }
    """),
});

var seenHand = hand.Json<JsonObject>()!;
Console.WriteLine($"{seenHand["ja3_hash"]} {seenHand["akamai_hash"]}");
Console.WriteLine(string.Join("|", hand.Warnings));   // unknown client_data option "not_a_real_option" ignored
```

## Vendoring instead of packaging

`Ja3.cs` is one file with no dependencies: add it to your project and put the library
somewhere it can find it — `make -C cffi host` builds it for this machine, and
`JA3_CLIENT_LIB` or `new Ja3(path)` points at it.

## Further reading

The full ABI — the six export functions, the JSON envelope, the C header — is documented
in [cffi/README.md](https://github.com/smallerqiu/ja3-client/blob/master/cffi/README.md),
and how the three packages are built and shipped is in
[PACKAGING.md](https://github.com/smallerqiu/ja3-client/blob/master/cffi/PACKAGING.md).
This file is the whole API for the common cases and does not depend on either.
