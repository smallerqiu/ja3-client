# 🔥🔥🔥 ja3-client

**English** | [简体中文](Readme.zh-CN.md)

## Why

If you're having trouble with the fucking “just a moment” or fucking http status code 429 in your project, you might want to try using this. It may help you .
It has held up at 10 million concurrent requests in our own production use. It is safe to use.  

## Features

- Proxy support : HTTP ,HTTPS , Socks4 , Socks5, Socks5h
- Custom headers
- Custom JA3 string
- Custom H2 settings
- Random TLS extension order
- Custom TLS extension order
- Custom connection flow
- Custom header order
- Custom client identifier (Chrome, Firefox, Opera, Safari, iOS, iPadOS, Android, Tor, Brave ,360 ,UC...)
- Supported Http3 protocols

## Supported browsers

The following browsers can be impersonated.

| Browser    | Version                                                                                                                                                                                                                                                                                                                              |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Chrome     | chrome_155, chrome_154, chrome_153, chrome_152, chrome_151, chrome_150, chrome_149, chrome_148, chrome_147, chrome_146, chrome_145, chrome_144, chrome_143, chrome_142, chrome_141, chrome_140, chrome_139, chrome_138, chrome_137, chrome_136, chrome_135, chrome_134, chrome_133, chrome_132, chrome_131, chrome_130, chrome_129, chrome_128, chrome_127, chrome_126, chrome_125, chrome_124, chrome_123, chrome_122, chrome_121, chrome_120, chrome_119, chrome_117, chrome_137_ios, chrome_131_android, chrome_99_android |
| Firefox    | firefox_144, firefox_143, firefox_142, firefox_141, firefox_140, firefox_139, firefox_138, firefox_137, firefox_136, firefox_135, firefox_134, firefox_133, firefox_132, firefox_123, firefox_120, firefox_117 |
| Safari Mac | safari_26_0, safari_18_5, safari_18_1, safari_18_0, safari_17_0, safari_15_5, safari_15_3 |
| Safari IOS | safari_ios_17_0, safari_ios_18_0, safari_ios_18_5, safari_ios_26_0                                                                                                                                                                                                                                                                   |
| Edge       | edge_140,edge_139, edge_138, edge_137, edge_136, edge_135, edge_134, edge_133, edge_132, edge_131, edge_101                                                                                                                                                                                                                          |
| Opera      | opera_120, opera_119, opera_117                                                                                                                                                                                                                                                                                                      |
| 360        | qh360_16_0, qh360_5_5_ios |
| UC         | uc_17_9                                                                                                                                                                                                                                                                                                                              |
| Xiaomi     | xiaomi_15_9                                                                                                                                                                                                                                                                                                                          |
| Samsung    | samsung_27_1                                                                                                                                                                                                                                                                                                                         |
| Tor        | tor_14_5                                                                                                                                                                                                                                                                                                                             |
| Brave      | brave_1_8 |

81 identifiers in total. [`ja3/mapper_profiles.go`](ja3/mapper_profiles.go) is the authoritative list, and the keys are case-sensitive.

Heads-up: a typo in `Impersonate` does not return an error. `BuildClientHelloSpec` logs `the input client ... don't support, so use default` and quietly falls back to `chrome_141`, so a mis-cased value looks like it worked while you are sending Chrome's fingerprint. Check that log line (or `WithDebug`) if the fingerprint site disagrees with you.

## Dependencies

```bash
golang >= 1.26
```

`go.mod` declares `go 1.26.0`, which is forced by `golang.org/x/net v0.61.0` and `golang.org/x/crypto v0.58.0` (both require Go 1.26). Go 1.21+ ships `GOTOOLCHAIN=auto`, so an older local toolchain still builds this module by downloading Go 1.26 on demand.

## Installation

```bash
go get github.com/smallerqiu/ja3-client
```

## Usage

### Basic Usage

default impersonate `chrome_141` (`ja3.DefaultImpersonate`), but you can set your customized ja3 string or another browser and version.

```go
package main

import (
 "io"
 "log"

 tls "github.com/smallerqiu/ja3-client"
)

func main() {
	// Get / Post / Put / Delete are available for one-off requests.
	// Note: these helpers build a throwaway client per call and do not follow
	// redirects; use CreateSession when you want cookie and connection reuse.
	response, err := tls.Get("https://tls.browserleaks.com/json", nil)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("read response body failed: %v", err)
	}

	log.Printf("status %d, body: %s", response.StatusCode, bytes)
}
```

## Custom ja3 string

use custom ja3 string do http request .
If you're going to use a customized JA3 , you'd better know the browser type.  Or you can just use the Custom Client

`Ja3Request` lives in the `ja3` subpackage — the root package does not re-export it, so both imports are needed.

The profile is picked in this order: `Ja3` (custom JA3 string) → `ClientData` (fully custom fingerprint) → `Impersonate` (built-in browser, default `chrome_141`).

```go
package main

import (
	"io"
	"log"

	tls "github.com/smallerqiu/ja3-client"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func main() {
	reqBody := &ja3.Ja3Request{
		Method: "GET",
		URL:    "https://tls.browserleaks.com/json",
		Ja3:    "771,4867-4865-4866-52393-52392-49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
		// Proxy:   "http://127.0.0.1:7890",         // optional
		// Headers: make(map[string][]string),       // optional, your custom headers
		// Akamai:  "1:65535;2:0;4:5840;6:262144|15663105|0|m,a,s,p", // optional, keeps the HTTP2 fingerprint accurate
		// RandomExtensionOrder: true,               // optional, randomizes the TLS extension order
	}

	response, err := tls.DoRequest(reqBody)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("read response body failed: %v", err)
	}

	log.Printf("%s %s -> %d", reqBody.Method, reqBody.URL, response.StatusCode)
	log.Printf("Response: %s", bytes)
}
```

Runnable version: `go run ./example/ja3string`

## Custom Client

```go
package main

import (
	"io"
	"log"

	tls "github.com/smallerqiu/ja3-client"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func main() {
	reqBody := &ja3.Ja3Request{
		Method:      "GET",
		URL:         "https://tls.browserleaks.com/json",
		Impersonate: "chrome_136",
		// Proxy:   "http://127.0.0.1:7890",   // optional
		// Headers: make(map[string][]string), // optional
		// RandomExtensionOrder: true,         // optional, randomizes the extension order
	}

	response, err := tls.DoRequest(reqBody)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("read response body failed: %v", err)
	}

	log.Printf("%s %s -> %d", reqBody.Method, reqBody.URL, response.StatusCode)
	log.Printf("Response: %s", bytes)
}

```

Runnable version: `go run ./example/impersonate`

## Reusing a session

`DoRequest` builds a client per call and closes idle connections when it returns, so every call does a fresh TCP + TLS handshake. For anything beyond a smoke test, build one client with `CreateSession` and keep it around — it is safe for concurrent use and carries cookies in its own jar.

```go
package main

import (
	"io"
	"log"

	tls "github.com/smallerqiu/ja3-client"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func main() {
	client, err := tls.CreateSession(&ja3.Ja3Request{
		Impersonate: "chrome_140",
		Timeout:     30,
	})
	if err != nil {
		log.Fatalf("create session failed: %v", err)
	}
	defer client.CloseIdleConnections()

	response, err := client.Get("https://tls.browserleaks.com/json")
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("read response body failed: %v", err)
	}

	log.Printf("status %d, body: %s", response.StatusCode, bytes)
}
```

## Options

| Name        | Description                                                                     | Type        | Default         | Optional | example                  |
| :---------- | :------------------------------------------------------------------------------ | :---------- | :-------------- | :------- | :----------------------- |
| Method      | request type                                                                    | string      | -               | No       | GET, POST ,PUT, DELETE   |
| URL         | request url                                                                     | string      | -               | No       | `https://example.com`      |
| Body        | request body                                                                    | []byte      | -               | Yes      | `[]byte("{\"a\": 1}")`   |
| Proxy       | request proxy url                                                               | string      | -               | Yes      | `http://198.168.1.55:7890` |
| SourceIP    | if your server has multiple IPs,you can decide on one of them as the source IP. | string      | -               | Yes      | 193.189.xx.xx            |
| Impersonate | which type of browser to impersonate                                            | string      | chrome_141      | Yes      | chrome_137               |
| Ja3         | customized ja3 key                                                              | string      | -               | Yes      | 771,4867-4865-....        |
| Akamai      | customized akamai key                                                           | string      | chrome's akamai | Yes      | 1:65535;2:0;4:...        |
| Timeout     | the timeout for the request.                                                    | int         | 30(s)           | Yes      | 60                       |
| ForceHTTP1  | skip ALPN-based HTTP2/HTTP3 selection and stay on HTTP/1.1                       | bool        | false           | Yes      | true                     |
| WithDebug   | log raw request/response sizes and headers                                         | bool        | false           | Yes      | true                     |
| ClientData  | if you want to customized a browser's fingerprint, you can set this options     | *ClientData | -               | Yes      | ....                     |

## From Node, Python or C#

`cffi/` builds this same library as one shared object with a small C ABI
(JSON in, JSON out), and [`cffi/README.md`](cffi/README.md) is the contract: payload
fields, the response envelope, the error codes, and the memory rules that ctypes/koffi
callers get wrong.

| binding | dependency | package |
| --- | --- | --- |
| [`cffi/bindings/python`](cffi/bindings/python/ja3_client.py) | none (ctypes) | `ja3-client` on PyPI |
| [`cffi/bindings/node`](cffi/bindings/node/index.js) | `koffi` | `ja3-client` on npm |
| [`cffi/bindings/csharp`](cffi/bindings/csharp/Ja3.cs) | none (P-Invoke) | `ja3-client` on NuGet |

The three packages carry the binding and a resolver, never the library: their install
step downloads `ja3-client-<version>-<os>-<arch>.zip` from the GitHub Release with the
same version and checks it against `SHA256SUMS.txt` first. That contract - the asset
names, the shared cache under `~/.cache/ja3-client`, the `JA3_CLIENT_*` variables, and
the failure message every binding gives when the download is not possible - is written
down in [`cffi/PACKAGING.md`](cffi/PACKAGING.md).

`ja3-client` is not on those three registries yet, so today you take the binding file and
the library yourself:

```sh
pip install /path/to/cffi/bindings/python      # or npm pack / dotnet pack locally
export JA3_CLIENT_LIB=/path/to/ja3_client_arm64.dylib
```

```python
from ja3_client import Ja3

ja3 = Ja3()
print(ja3.get("https://tls.browserleaks.com/json", impersonate="chrome_140").json()["ja3n_hash"])

with ja3.session(impersonate="chrome_140") as session:   # one connection pool, one cookie jar
    session.get("https://httpbin.org/cookies")
```

Releases carry prebuilt libraries (`libja3_client_<arch>.so`,
`ja3_client_<arch>.dll` / `.lib`, `ja3_client_<arch>.dylib`) as zips, each with the
generated header and `smoke.py`, so you can check the file you downloaded before
writing any code against it. Build your own with `make` in `cffi/`.

## Reporting problems

The issue forms ask for the two things that make a TLS report fixable: the version the
library reports (`ja3_version()` / `python3 smoke.py`), and captures from both the real
browser and this library against the same endpoint on the same day.

* **Bug report** - anything that does not behave as documented.
* **Fingerprint mismatch** - the browser and this library send different bytes.
* **New browser version** - a profile that does not exist yet; bring the capture.

Want to add one yourself? [CONTRIBUTING.md](CONTRIBUTING.md) is the whole procedure, from
capturing the bytes to landing the profile.

One thing worth knowing before you file: a typo in `Impersonate` is not an error, so the
note under [Supported browsers](#supported-browsers) is the first thing to rule out.

Of course, you can also look at other projects, such as [curl_cffi](https://github.com/lexiforest/curl_cffi), [REQ](https://github.com/imroc/req) etc.
