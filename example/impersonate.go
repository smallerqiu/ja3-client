package main

import (
	"io"
	"log"

	client "github.com/smallerqiu/ja3-client"
)

/*
Impersonate list of client :
"custom"
"qq_13_5"
"uc_17_3"
"360_14_5"
"xiaomi_15_9"
"sansung_27_1"
"chrome_103"
"chrome_104"
"chrome_105"
"chrome_106"
"chrome_107"
"chrome_108"
"chrome_109"
"chrome_110"
"chrome_111"
"chrome_112"
"chrome_116_PSK"
"chrome_116_PSK_PQ"
"chrome_117"
"chrome_120"
"chrome_124"
"chrome_131"
"chrome_131_PSK"
"chrome_133"
"chrome_133_PSK"
"safari_15_6_1"
"safari_16_0"
"safari_18_1"
"safari_ipad_15_6"
"safari_ios_15_5"
"safari_ios_15_6"
"safari_ios_16_0"
"safari_ios_16_7"
"safari_ios_17_0"
"safari_ios_18_0"
"firefox_102"
"firefox_105"
"firefox_106"
"firefox_108"
"firefox_110"
"firefox_117"
"firefox_120"
"firefox_123"
"firefox_124"
"firefox_132"
"firefox_133"
"firefox_135"
"opera_89"
"opera_90"
"opera_91"
"opera_117"
"edge_133"
"zalando_android_mobile":
"zalando_ios_mobile"
"nike_ios_mobile"
"nike_android_mobile"
"cloudscraper"
"mms_ios"
"mms_ios_1"
"mms_ios_2"
"mms_ios_3"
"mesh_ios"
"mesh_ios_1"
"mesh_ios_2"
"mesh_android"
"mesh_android_1"
"mesh_android_2"
"confirmed_ios"
"confirmed_android"
"okhttp4_android_7"
"okhttp4_android_8"
"okhttp4_android_9"
"okhttp4_android_10"
"okhttp4_android_11"
"okhttp4_android_12"
"okhttp4_android_13"
*/

func testImpersonate() {
	reqBody := &client.Ja3Request{
		Method:               "GET",
		URL:                  "https://www.google.com",
		Proxy:                "http://127.0.0.1:8080",
		Headers:              make(map[string][]string),
		Impersonate:          "chrome_133",
		RandomExtensionOrder: true,
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
