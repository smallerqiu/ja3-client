# 🔥🔥🔥 ja3-client

[English](Readme.md) | **简体中文**

## 为什么需要它

如果你的项目正被该死的「just a moment」验证页，或者 HTTP 429 状态码卡住，可以试试这个库，
它也许能帮上忙。一千万并发请求是我们在实际生产使用中跑出来的结果，可放心使用。

## 特性

- 代理支持：HTTP、HTTPS、Socks4、Socks5、Socks5h
- 自定义请求头
- 自定义 JA3 字符串
- 自定义 H2 settings
- 随机 TLS 扩展顺序
- 自定义 TLS 扩展顺序
- 自定义连接流程
- 自定义请求头顺序
- 自定义客户端标识（Chrome、Firefox、Opera、Safari、iOS、iPadOS、Android、Tor、Brave、360、UC……）
- 支持 Http3 协议

## 支持的浏览器

以下浏览器可以被模拟。

| 浏览器     | 版本                                                                                                                                                                                                                                                                                                                              |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Chrome     | chrome_155, chrome_154, chrome_153, chrome_152, chrome_151, chrome_150, chrome_149, chrome_148, chrome_147, chrome_146, chrome_145, chrome_144, chrome_143, chrome_142, chrome_141, chrome_140, chrome_139, chrome_138, chrome_137, chrome_136, chrome_135, chrome_134, chrome_133, chrome_132, chrome_131, chrome_130, chrome_129, chrome_128, chrome_127, chrome_126, chrome_125, chrome_124, chrome_123, chrome_122, chrome_121, chrome_120, chrome_119, chrome_117, chrome_137_ios, chrome_131_android, chrome_99_android |
| Firefox    | firefox_144, firefox_143, firefox_142, firefox_141, firefox_140, firefox_139, firefox_138, firefox_137, firefox_136, firefox_135, firefox_134, firefox_133, firefox_132, firefox_123, firefox_120, firefox_117 |
| Safari Mac | safari_26_0, safari_18_5, safari_18_1, safari_18_0, safari_17_0, safari_15_5, safari_15_3 |
| Safari IOS | safari_ios_17_0, safari_ios_18_0, safari_ios_18_5, safari_ios_26_0                                                                                                                                                                                                                                                                   |
| Edge       | edge_140,edge_139, edge_138, edge_137, edge_136, edge_135, edge_134, edge_133, edge_132, edge_131, edge_101                                                                                                                                                                                                                          |
| Opera      | opera_120, opera_119, opera_117                                                                                                                                                                                                                                                                                                      |
| 360        | qh360_16_0, qh360_5_5_ios |
| UC         | uc_ios_17_9                                                                                                                                                                                                                                                                                                                          |
| Xiaomi     | xiaomi_15_9                                                                                                                                                                                                                                                                                                                          |
| Samsung    | samsung_27_1                                                                                                                                                                                                                                                                                                                         |
| Tor        | tor_14_5                                                                                                                                                                                                                                                                                                                             |
| Brave      | brave_1_8 |

共 81 个标识。[`ja3/mapper_profiles.go`](ja3/mapper_profiles.go) 是唯一权威的列表，键名区分大小写。

注意：`Impersonate` 写错不会返回错误。`BuildClientHelloSpec` 会打印
`the input client ... don't support, so use default`，然后悄悄退回到 `chrome_155`——所以拼错的值
看起来像是生效了，而你实际发出的是 Chrome 的指纹。如果指纹检测网站和你的判断不一致，先去看这行日志
（或者打开 `WithDebug`）。

## 依赖

```bash
golang >= 1.26
```

`go.mod` 声明的是 `go 1.26.0`，这是被 `golang.org/x/net v0.61.0` 和 `golang.org/x/crypto v0.58.0`
（两者都要求 Go 1.26）顶上去的。Go 1.21+ 自带 `GOTOOLCHAIN=auto`，所以本地即使装着更旧的工具链，
也能按需下载 Go 1.26 来构建本模块。

## 安装

```bash
go get github.com/smallerqiu/ja3-client
```

## 使用

### 基本用法

默认模拟 `chrome_155`（`ja3.DefaultImpersonate`），你也可以设置自定义的 ja3 字符串，或者换一个浏览器及版本。

```go
package main

import (
 "io"
 "log"

 tls "github.com/smallerqiu/ja3-client"
)

func main() {
	// 单次请求可以用 Get / Post / Put / Delete。
	// 注意：这些快捷方法每次都会新建一个客户端，且不会跟随重定向；
	// 需要复用 cookie 和连接时请使用 CreateSession。
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

## 自定义 ja3 字符串

用自定义的 ja3 字符串发请求。
如果你打算用自定义 JA3，最好清楚自己面对的是哪种浏览器；否则直接用 Custom Client 就好。

`Ja3Request` 在 `ja3` 子包里——根包没有重新导出它，所以两个 import 都要写。

profile 的选取顺序是：`Ja3`（自定义 JA3 字符串）→ `ClientData`（完全自定义指纹）→
`Impersonate`（内置浏览器，默认 `chrome_155`）。

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
		// Proxy:   "http://127.0.0.1:7890",         // 可选
		// Headers: make(map[string][]string),       // 可选，你的自定义请求头
		// Akamai:  "1:65535;2:0;4:5840;6:262144|15663105|0|m,a,s,p", // 可选，让 HTTP2 指纹保持准确
		// RandomExtensionOrder: true,               // 可选，随机化 TLS 扩展顺序
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

可直接运行的版本：`go run ./example/ja3string`

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
		// Proxy:   "http://127.0.0.1:7890",   // 可选
		// Headers: make(map[string][]string), // 可选
		// RandomExtensionOrder: true,         // 可选，随机化扩展顺序
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

可直接运行的版本：`go run ./example/impersonate`

## 复用同一个 session

`DoRequest` 每次调用都新建客户端，并在返回时关闭空闲连接，所以每一次请求都要重新做 TCP + TLS 握手。
只要不是冒烟测试，就用 `CreateSession` 建一个客户端长期持有——它支持并发使用，cookie 也存在自己独立的 jar 里。

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

## 选项

| 名称        | 说明                                                                          | 类型        | 默认值          | 是否可选 | 示例                     |
| :---------- | :------------------------------------------------------------------------------ | :---------- | :-------------- | :------- | :----------------------- |
| Method      | 请求类型                                                                        | string      | -               | 否       | GET, POST ,PUT, DELETE   |
| URL         | 请求地址                                                                        | string      | -               | 否       | `https://example.com`      |
| Body        | 请求体                                                                          | []byte      | -               | 是       | `[]byte("{\"a\": 1}")`   |
| Proxy       | 代理地址                                                                        | string      | -               | 是       | `http://198.168.1.55:7890` |
| SourceIP    | 服务器有多个 IP 时，可以指定其中一个作为源 IP。                                 | string      | -               | 是       | 193.189.xx.xx            |
| Impersonate | 模拟哪一种浏览器                                                                | string      | chrome_155      | 是       | chrome_137               |
| Ja3         | 自定义 ja3 key                                                                  | string      | -               | 是       | 771,4867-4865-....        |
| Akamai      | 自定义 akamai key                                                               | string      | chrome 的 akamai | 是      | 1:65535;2:0;4:...        |
| Timeout     | 请求超时时间。                                                                  | int         | 30(秒)          | 是       | 60                       |
| ForceHTTP1  | 跳过基于 ALPN 的 HTTP2/HTTP3 选择，强制走 HTTP/1.1                              | bool        | false           | 是       | true                     |
| WithDebug   | 打印原始请求/响应的大小与请求头                                                   | bool        | false           | 是       | true                     |
| ClientData  | 想自定义某个浏览器的指纹时，用这个选项                                            | *ClientData | -               | 是       | ....                     |

## 在 Node、Python 或 C# 里使用

`cffi/` 会把同一个库编译成一个共享对象，对外只暴露很小的 C ABI（JSON 进，JSON 出），
[`cffi/README.md`](cffi/README.md) 就是这份契约：payload 字段、响应信封、错误码，以及
ctypes/koffi 调用方最容易搞错的内存规则。

| binding | 依赖 | 包 |
| --- | --- | --- |
| [`cffi/bindings/python`](cffi/bindings/python/ja3_client.py) | 无（ctypes） | PyPI 上的 `ja3-client` |
| [`cffi/bindings/node`](cffi/bindings/node/index.js) | `koffi` | npm 上的 `ja3-client` |
| [`cffi/bindings/csharp`](cffi/bindings/csharp/Ja3.cs) | 无（P-Invoke） | NuGet 上的 `ja3-client` |

三个包都只带 binding 代码和负责找库、取库的解析逻辑，绝不带库本身：安装步骤会去下载同版本 GitHub Release 里的
`ja3-client-<version>-<os>-<arch>.zip`，并先用 `SHA256SUMS.txt` 校验。这份契约——资产命名、
`~/.cache/ja3-client` 下的共享缓存、`JA3_CLIENT_*` 环境变量，以及下载不到时每个 binding 给出的那条
错误信息——都写在 [`cffi/PACKAGING.md`](cffi/PACKAGING.md) 里。

`ja3-client` 还没上架这三个注册表，所以现在要你自己分别取 binding 文件和库：

```sh
pip install /path/to/cffi/bindings/python      # 或者本地 npm pack / dotnet pack
export JA3_CLIENT_LIB=/path/to/ja3_client_arm64.dylib
```

```python
from ja3_client import Ja3

ja3 = Ja3()
print(ja3.get("https://tls.browserleaks.com/json", impersonate="chrome_140").json()["ja3n_hash"])

with ja3.session(impersonate="chrome_140") as session:   # 一个连接池，一个 cookie jar
    session.get("https://httpbin.org/cookies")
```

每个 Release 都带有预编译好的库（`libja3_client_<arch>.so`、`ja3_client_<arch>.dll` / `.lib`、
`ja3_client_<arch>.dylib`），打包成 zip，里面同时有生成的头文件和 `smoke.py`，所以你可以在对着它写
任何代码之前，先确认下载下来的文件是好的。想自己构建就在 `cffi/` 里执行 `make`。

## 反馈问题

Issue 模板会要两样东西，它们决定了一份 TLS 报告到底能不能被修：库自报的版本号（`ja3_version()` /
`python3 smoke.py`），以及同一天、同一个检测端点上，真实浏览器和这个库各自的抓包。

* **Bug report** - 任何与文档不符的行为。
* **Fingerprint mismatch** - 浏览器和这个库发出的字节不一致。
* **New browser version** - 还不存在的 profile；请带上抓包。

想自己加一个？[CONTRIBUTING.md](CONTRIBUTING.md) 写了完整流程，从抓下这些字节到 profile 落地。

提 issue 之前值得知道的一点：`Impersonate` 拼错不算错误，所以先按
[支持的浏览器](#支持的浏览器) 那条提示排除这种情况。

当然，你也可以看看别的项目，比如 [curl_cffi](https://github.com/lexiforest/curl_cffi)、
[REQ](https://github.com/imroc/req) 等。
