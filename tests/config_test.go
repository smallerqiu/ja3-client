package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	ja3client "github.com/smallerqiu/ja3-client"
	"github.com/smallerqiu/ja3-client/http"
	"github.com/smallerqiu/ja3-client/ja3"
)

func TestConfig(t *testing.T) {
	// impersonate := "samsung_27_1"
	// clientProfile, err := ja3.BuildClientHelloSpec(impersonate)

	// chrome138
	impersonate := "chrome_136"
	akamai_text := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	ja3_text := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17613-27-5-16-11-18-45-65281-43-0-13-23-65037-51-10-35,4588-29-23-24,0"
	clientProfile, err := ja3.BuildClientHelloSpecFromJa3Key(ja3_text, akamai_text)

	// clientProfile, err := ja3.BuildClientHelloSpec(ja3.QH360_5_5_ios)

	// test := browser.Safari_18_1

	// m, _ := clientProfile.ClientHelloId.SpecFactory()
	// n, _ := test.ClientHelloId.SpecFactory()

	// print(clientProfile.ClientHelloId.Version)
	// print(c136.ClientHelloId.Version)
	// print(m.TLSVersMin, n.TLSVersMin)
	fmt.Printf("\n\n\n\n")
	if err != nil {
		fmt.Printf("profile %s", err)
		return
	}
	options := []ja3client.HttpClientOption{
		ja3client.WithForceHttp1(false),
		ja3client.WithNotFollowRedirects(),
		ja3client.WithClientProfile(clientProfile),
		// ja3client.WithClientProfile(c136),
		ja3client.WithTimeoutSeconds(10),
		// ja3client.WithProxyUrl("http://127.0.0.1:7890"),
	}

	client, err := ja3client.NewHttpClient(ja3client.NewNoopLogger(), options...)

	if err != nil {
		fmt.Printf("client %s", err)
		return
	}
	var tlsApi = "https://tls.browserleaks.com/json"

	req, err := http.NewRequest("GET", tlsApi, nil)
	Headers := http.Header{
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
	}
	for k, v := range Headers {
		req.Header.Set(k, strings.Join(v, ", "))
	}
	if err != nil {
		fmt.Printf("req %s", err)
		return
	}
	response, err := client.Do(req)
	if err != nil {
		fmt.Printf("res %s", err)
		return
	}
	defer client.CloseIdleConnections()
	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("io %s", err)
		return
	}

	// print(string(bytes))

	tlsinfo := TlsInfo{}
	if err := json.Unmarshal(bytes, &tlsinfo); err != nil {
		t.Error(err)
	}

	info := TlsInfoMap[impersonate]

	// just match the ja3n_hash , ja4 , akamai_hash

	if !clientProfile.ClientHelloId.RandomExtensionOrder {
		if tlsinfo.Ja3Text != info["ja3_text"] {
			fmt.Printf("cur ja3: %v \n", tlsinfo.Ja3Text)
			fmt.Printf("tar ja3: %v \n", info["ja3_text"])
			t.Errorf("ja3 mismatch")
		}
	}
	if tlsinfo.Ja3nHash != info["ja3n_hash"] {
		fmt.Printf("cur ja3: %v \n", tlsinfo.Ja3Text)
		fmt.Printf("tar ja3: %v \n", info["ja3_text"])
		t.Errorf("ja3 hash mismatch")
	}
	if tlsinfo.Ja4 != info["ja4"] {
		fmt.Printf("cur ja4: %v \n", tlsinfo.Ja4)
		fmt.Printf("tar ja4: %v \n", info["ja4"])
		t.Errorf("ja4 mismatch")
	}
	if tlsinfo.AkamaiHash != info["akamai_hash"] {
		// fmt.Printf("cur ja4: %v \n", tlsinfo.Ja4)
		// fmt.Printf("tar ja4: %v \n", info["ja4"])
		fmt.Printf("cur akamai_text: %v \n", tlsinfo.AkamaiText)
		t.Errorf("akamai mismatch")
	}

}
