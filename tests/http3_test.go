package tests

import (
	"io"
	"strings"
	"testing"

	client "github.com/smallerqiu/ja3-client"
	http "github.com/smallerqiu/ja3-client/http"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

var defaultHeader = http.Header{
	"accept":          {"*/*"},
	"accept-encoding": {"gzip"},
	"accept-language": {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
	// "user-agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0"},
	http.HeaderOrderKey: {
		"accept",
		"accept-encoding",
		"accept-language",
		"user-agent",
	},
}

func TestHTTP3(t *testing.T) {

	options := ja3.Ja3Request{
		Method:      "GET",
		URL:         "https://http3.is/",
		Impersonate: "chrome_133", // because we enabled HTTP3 for chrome 133, so other browsers will not be able to connect
		Timeout:     30,
		Headers:     defaultHeader,
		WithDebug:   true,
		Proxy:       "http://127.0.0.1:7890",
	}

	resp, err := client.DoRequest(&options)
	if err != nil {
		println(err)
		t.Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(body), "it does support HTTP/3!") {
		t.Fatal("Response did not contain HTTP3 result")
	}
}

func TestDisableHTTP3(t *testing.T) {
	options := ja3.Ja3Request{
		Method:       "GET",
		URL:          "https://http3.is/",
		Impersonate:  "chrome_133", // because we enabled HTTP3 for chrome 133, so other browsers will not be able to connect
		Timeout:      30,
		DisableHTTP3: true,
		WithDebug:    true,
		Headers:      defaultHeader,
		Proxy:        "http://127.0.0.1:7890",
	}

	resp, err := client.DoRequest(&options)

	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(body), "HTTP/3 (h3-29 or h3-27) was not used to request this page") {
		t.Fatal("Response did contain HTTP3 result")
	}
}
