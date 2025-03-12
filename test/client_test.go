package test

import (
	"io"
	"log"
	"testing"

	tls "github.com/smallerqiu/ja3-client"
)

func TestClient(t *testing.T) {
	reqBody := &tls.Ja3Request{
		Method:               "GET",
		URL:                  "https://tls.browserleaks.com/json",
		Proxy:                "http://127.0.0.1:7890",
		Headers:              make(map[string][]string),
		Impersonate:          "chrome_133",
		RandomExtensionOrder: true,
	}
	// 创建 TLS 会话
	var client, request, err = tls.CreateSession(reqBody)

	if err != nil {
		log.Printf("Client Error: %v", err)
	}

	response, err := client.Do(request)
	defer client.CloseIdleConnections()

	if err != nil {
		log.Printf("Error response: %v", err)
	}

	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)

	if err != nil {
		log.Printf("Error response: %v", err)
	}

	log.Printf("Response: %s", string(bytes))

	log.Printf("%v,%s: %s", response.StatusCode, reqBody.Method, reqBody.URL)
}
