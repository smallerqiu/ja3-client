package main

import (
	"io"
	"log"
	"testing"

	tls "github.com/smallerqiu/ja3-client"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func TestClient(t *testing.T) {
	// var akamai = "1:65535;2:0;4:5840;6:262144|15663105|0|m,a,s,p"
	reqBody := &ja3.Ja3Request{
		Method: "GET",
		URL:    "https://onlyfans.com/",
		Proxy:  "http://127.0.0.1:7890",
		// Headers: http.Header{
		// 	"sec-ch-ua":          {"\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\""},
		// 	"sec-ch-ua-mobile":   {"?0"},
		// 	"sec-ch-ua-platform": {"\"macOS\""},
		// 	"sec-fetch-site":     {"same-origin"},
		// 	"sec-fetch-mode":     {"cors"},
		// 	"sec-fetch-dest":     {"empty"},
		// 	"app-token":          {"33d57ade8c02dbc5a333db99ff9ae26a"},
		// 	"x-bc":               {"2dc18e45c18185ae523daadac916d2599cf778b7"},
		// 	"x-of-rev":           {"202502041753-f12c785993"},
		// 	"time":               {"1742439722414"},
		// 	"cookie":             {"lang=en; fp=32d46e15fc474a0ff56a7ee89c418190600d0a25; cookiesAccepted=all; csrf=NUxbObA4953b47ca7e42ad835eb8efdccb2939da; auth_id=380414657; st=3a1e1e600e54a99490d0fe41560d379005c852ff3b44f692e8255e623955a463; ref_src=; _cfuvid=2mdEaBFWNABk94dVTrKCsAR4ewppZq3rtz.GNrQi9Vc-1742187106000-0.0.1.1-604800000; sess=hcr0evdo8u8lm7933qtt0afcrk; __cf_bm=7zuk9AJDSHoIGETFAr6j5i8uz1192Ojp5cDgoI_mAVo-1742471359-1.0.1.1-I8OfFm8aKZIX9T0s1p3NpmP4IgfLhqzTJBAEjljlUt.HHu.3.YRHKhEpDZJrs_0J6ZAy2bY7RwxsbdHUSNkzdO6YR4pkMlDfFZGT2iPxy3A"},
		// 	"sign":               {"38674:ec915446493af0350027bd92a2e09e41682fbe92:ae9:67dae8fc"},
		// 	"accept":             {"application/json, text/plain, */*"},
		// 	"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"},
		// },
		Impersonate: "chrome_140",
		// Akamai:      akamai,
		// Ja3:    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-255,0-11-10-35-16-22-23-13-43-45-51-21,29-23-24-25497,0",
	}
	var response, err = tls.DoRequest(reqBody)

	if err != nil {
		log.Printf("Client Error: %v", err)
	}

	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)

	if err != nil {
		log.Printf("Error response: %v", err)
	}

	log.Printf("Response: %s", string(bytes))

	log.Printf("%v,%s: %s", response.StatusCode, reqBody.Method, reqBody.URL)
}
