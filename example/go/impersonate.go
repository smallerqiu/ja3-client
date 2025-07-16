package main

import (
	"io"
	"log"

	tls "github.com/smallerqiu/ja3-client"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func TestImpersonate() {
	reqBody := &ja3.Ja3Request{
		Method:               "GET",
		URL:                  "https://www.google.com",
		Proxy:                "http://127.0.0.1:7890",
		Headers:              make(map[string][]string),
		Impersonate:          "chrome_133",
		RandomExtensionOrder: true,
	}
	var response, err = tls.DoRequest(reqBody)

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
