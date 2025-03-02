package test

import (
	"io"
	"log"
	"testing"

	client "github.com/smallerqiu/ja3-client"
)

func TestJa3Key(t *testing.T) {
	reqBody := &client.Ja3Request{
		Method:        "GET",
		URL:           "https://www.google.com",
		Proxy:         "http://127.0.0.1:7890",
		Headers:       make(map[string][]string),
		JA3String:     "771,4867-4865-4866-52393-52392-49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
		Client:        "Safari",
		ClientVersion: "18.1",
	}
	// 创建 TLS 会话
	var client, request, err = client.CreateSession(reqBody)

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
