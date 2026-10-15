// Command ja3string 演示用自定义 JA3 串（可选再配 Akamai HTTP2 指纹）发起请求。
//
//	go run ./example/ja3string
//	go run ./example/ja3string -akamai '1:65535;2:0;4:5840;6:262144|15663105|0|m,a,s,p'
//
// 只给 JA3 时 UA 等 HTTP 头不会被自动改掉，指纹站点仍可能看出不一致；
// 想要完整仿冒请用 -impersonate（见 example/impersonate）。
package main

import (
	"flag"
	"io"
	"log"

	tls "github.com/smallerqiu/ja3-client"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

const defaultJa3 = "771,4867-4865-4866-52393-52392-49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"

func main() {
	requestURL := flag.String("url", "https://tls.browserleaks.com/json", "请求地址")
	ja3Key := flag.String("ja3", defaultJa3, "自定义 JA3 串")
	akamai := flag.String("akamai", "", "自定义 Akamai HTTP2 指纹，留空则用默认值")
	proxy := flag.String("proxy", "", "代理地址，如 http://127.0.0.1:7890，留空则直连")
	flag.Parse()

	reqBody := &ja3.Ja3Request{
		Method: "GET",
		URL:    *requestURL,
		Ja3:    *ja3Key,
	}

	if *akamai != "" {
		reqBody.Akamai = *akamai
	}

	if *proxy != "" {
		reqBody.Proxy = *proxy
	}

	response, err := tls.DoRequest(reqBody)
	if err != nil {
		log.Fatalf("请求失败: %v", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("读取响应失败: %v", err)
	}

	log.Printf("%s %s -> %d", reqBody.Method, reqBody.URL, response.StatusCode)
	log.Printf("响应内容: %s", body)
}
