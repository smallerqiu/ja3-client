# 🔥🔥🔥 ja3-client 
If you're having trouble with the fucking “just a moment” or fucking status code 429 in your project, you might want to try using this. It may help you . 

Demonstrates good performance with 10 million concurrent requests. It is safe to use.  Of course, you can also look at other projects, such as [curl_cffi](https://github.com/lexiforest/curl_cffi), [REQ](https://github.com/imroc/req) etc.

# Features
 - Proxy support : HTTP ,HTTPS , Socks4 , Socks5, Socks5h
 - Custom headers
 - Custom JA3 string
 - Custom H2 settings
 - Random TLS extension order
 - Custom TLS extension order
 - Custom connection flow
 - Custom header order
 - Custom client identifier (Chrome, Firefox, Opera, Safari, iOS, iPadOS, Android)

# Supported browsers

The following browsers can be impersonated.

| Browser     | Version                                                                                                                                                                                                                                                                                                             |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Chrome      | chrome_103, chrome_104, chrome_105, chrome_106, chrome_107, chrome_108, chrome_109,chrome_110, chrome_111, chrome_112, chrome_116, chrome_117,chrome_119, chrome_120, chrome_122, chrome_124, chrome_125, chrome_126, chrome_127, chrome_128, chrome_129, chrome_130, chrome_131,chrome_132, chrome_133, chrome_134,chrome_135,chrome_136,chrome_137 |
| Firefox     | firefox_102, firefox_104, firefox_106, firefox_108, firefox_110, firefox_117, firefox_120, firefox_123, firefox_124, firefox_132, firefox_133, firefox_135, firefox_136, firefox_137, firefox_138 ,firefox_139|
| Safari Mac  | safari_15_3, safari_15_6_1,  safari_16_0, safari_17_0, safari_17_5, safari_18_0,  safari_18_1, safari_18_4,safari_18_5|
| Safari IOS  | safari_ios_15_5, safari_ios_15_6, safari_ios_16_0, safari_ios_16_7,safari_ios_17_0,safari_ios_18_0|
| Safari IPAD | safari_ipad_15_6|
| Edge        | edge_131, edge_133, edge_134, edge_136, edge_136|
| Opera       | opera_89, opera_90, opera_91, opera_117, opera_119|
| QQ          | qq_13_5|
| 360         | 360_14_5|
| UC          | uc_17_3|
| Xiaomi      | xiaomi_15_9|
| Sansung     | sansung_27_1|


# Dependencies
```
golang ^v1.21x
```

# Installation
```
$ go get github.com/smallerqiu/ja3-client
```

# Usage

## Custom ja3 string
use custom ja3 string do http request .
If you're going to use a customized JA3 , you'd better know the browser type.  Or you can just use the Custom Client
```go
package main

import (
	"io"
	"log"

	tls "github.com/smallerqiu/ja3-client"
)
/**
Client types :

"Firefox"
"QQ Browser Mobile"
"QQ Browser"
"Mobile Safari"
"Safari"
"MiuiBrowser"
"Samsung Internet"
"UC Browser"
"Opera"
"Edge"
"Chrome"
"360"
*/

func main() {
	reqBody := &tls.Ja3Request{
		Method:        "GET",
		URL:           "https://www.google.com",
		Proxy:         "http://127.0.0.1:7890",
		Headers:       make(map[string][]string),
		JA3String:     "771,4867-4865-4866-52393-52392-49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
		Client:        "Safari", // if you don't know the browser type , you can use `Chrome`
		ClientVersion: "18.1",	 // if you don't know the version , you can use `133`
	}
	
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
```

## Custom Client

```go
package main

import (
	"io"
	"log"

	tls "github.com/smallerqiu/ja3-client"
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

func main() {
	reqBody := &tls.Ja3Request{
		Method:               "GET",
		URL:                  "https://tls.browserleaks.com/json",
		Proxy:                "http://127.0.0.1:7890",
		Headers:              make(map[string][]string),
		Impersonate:          "chrome_133",
		RandomExtensionOrder: true,
	}
	
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

```
 