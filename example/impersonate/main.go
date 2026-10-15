// Command impersonate 演示用 Impersonate 直接仿冒某个浏览器的 TLS/HTTP2 指纹。
//
//	go run ./example/impersonate
//	go run ./example/impersonate -impersonate firefox_135
//	go run ./example/impersonate -proxy http://127.0.0.1:7890
package main

import (
	"flag"
	"io"
	"log"

	tls "github.com/smallerqiu/ja3-client"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func main() {
	requestURL := flag.String("url", "https://tls.browserleaks.com/json", "请求地址")
	impersonate := flag.String("impersonate", "chrome_133", "要仿冒的浏览器，如 chrome_133、firefox_135、safari_18_0")
	proxy := flag.String("proxy", "", "代理地址，如 http://127.0.0.1:7890，留空则直连")
	flag.Parse()

	reqBody := &ja3.Ja3Request{
		Method:               "GET",
		URL:                  *requestURL,
		Impersonate:          *impersonate,
		RandomExtensionOrder: true,
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
