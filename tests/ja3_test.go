package tests

import (
	"encoding/json"
	"io"
	"log"
	"testing"

	tls "github.com/smallerqiu/ja3-client"
	"github.com/smallerqiu/ja3-client/http"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func TestSimple(t *testing.T) {
	response, err := tls.Get("https://tls.browserleaks.com/json", nil)

	if err != nil {
		log.Printf("Error response: %v", err)
	}

	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)

	if err != nil {
		log.Printf("Error response: %v", err)
	}

	log.Printf("Response: %s", string(bytes))

	log.Printf("%v", response.StatusCode)
}

func TestClients(t *testing.T) {
	client, err := tls.CreateSession(&ja3.Ja3Request{
		Impersonate: "chrome_136",
	})

	if err != nil {
		log.Printf("Client Error response: %v", err)
		return
	}

	defer client.CloseIdleConnections()

	var res1, err1 = client.Get("https://www.chuchur.com")
	if err1 != nil {
		log.Printf("Error res1: %v", err)
		return
	}
	defer res1.Body.Close()
	log.Printf("result1: %v \n\n", res1.StatusCode)

	// todo:
	// var res2, err2 = client.Get("https://tls.browserleaks.com/json")
	// if err2 != nil {
	// 	log.Printf("Error res2: %v", err)
	// 	return
	// }
	// defer res2.Body.Close()
	// log.Printf("result2: %v \n\n", res2.StatusCode)
}

func TestJa3Key(t *testing.T) {
	// var peetApi = "https://tls.peet.ws/api/all"
	var api = "https://tls.browserleaks.com/json"
	var ja3key = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,10-65281-65037-23-34-16-28-27-5-43-11-13-0-51,4588-29-23-24-25-256-257,0"
	reqBody := &ja3.Ja3Request{
		Method: "GET",
		URL:    api,
		// Proxy:         "http://127.0.0.1:7890",
		Headers:       make(map[string][]string),
		Ja3:           ja3key,
		Client:        "Firefox",
		ClientVersion: "135",
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

	// log.Printf("Response: %s", string(bytes))
	info := &TlsInfo{}
	if err := json.Unmarshal(bytes, info); err != nil {
		log.Printf("Error response: %v", err)
	}
	log.Printf("cur:%v \n", ja3key)
	log.Printf("tar:%v \n\n", info.Ja3Text)

	// log.Printf("%v,%s: %s", response.StatusCode, reqBody.Method, reqBody.URL)

}

func TestClient(t *testing.T) {
	reqBody := &ja3.Ja3Request{
		Method: "GET",
		URL:    "https://www.chuchur.com",
		Proxy:  "http://127.0.0.1:7890",
		Headers: http.Header{
			"sec-ch-ua":          {"\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\""},
			"sec-ch-ua-mobile":   {"?0"},
			"sec-ch-ua-platform": {"\"macOS\""},
			"sec-fetch-site":     {"same-origin"},
			"sec-fetch-mode":     {"cors"},
			"sec-fetch-dest":     {"empty"},
			"app-token":          {"33d57ade8c02dbc5a333db99ff9ae26a"},
			"x-bc":               {"2dc18e45c18185ae523daadac916d2599cf778b7"},
			"x-of-rev":           {"202502041753-f12c785993"},
			"time":               {"1742439722414"},
			"cookie":             {"lang=en; fp=32d46e15fc474a0ff56a7ee89c418190600d0a25; cookiesAccepted=all; csrf=NUxbObA4953b47ca7e42ad835eb8efdccb2939da; auth_id=380414657; st=3a1e1e600e54a99490d0fe41560d379005c852ff3b44f692e8255e623955a463; ref_src=; _cfuvid=2mdEaBFWNABk94dVTrKCsAR4ewppZq3rtz.GNrQi9Vc-1742187106000-0.0.1.1-604800000; sess=hcr0evdo8u8lm7933qtt0afcrk; __cf_bm=7zuk9AJDSHoIGETFAr6j5i8uz1192Ojp5cDgoI_mAVo-1742471359-1.0.1.1-I8OfFm8aKZIX9T0s1p3NpmP4IgfLhqzTJBAEjljlUt.HHu.3.YRHKhEpDZJrs_0J6ZAy2bY7RwxsbdHUSNkzdO6YR4pkMlDfFZGT2iPxy3A"},
			"sign":               {"38674:ec915446493af0350027bd92a2e09e41682fbe92:ae9:67dae8fc"},
			"accept":             {"application/json, text/plain, */*"},
			"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"},
		},
		Impersonate: "chrome_134",
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
