package tests

import (
	"bytes"
	"compress/gzip"
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
	http.HeaderOrderKey: {
		"accept",
		"accept-encoding",
		"accept-language",
		"user-agent",
	},
}

// http3.is picks the page it serves from the protocol the request actually arrived on,
// which makes these two a live check on the flag: with the profile default there is no
// h3 in the ALPN list and the page says the request was not made over HTTP/3; with
// with_http3 set to true, Fastly negotiates h3 inside the TCP handshake, the client
// follows that answer with a real QUIC connection, and the success page comes back.
//
// The success page is the proof and the cost at once. That QUIC connection is built
// from a plain tls.Config with no ClientHelloID in it (roundtripper.go), so the hello on
// the wire is the library's own Go hello rather than the browser you asked to impersonate,
// it does not carry the profile's proxy or disableIPV4/6, and the body is not transparently
// decompressed the way the h2 path decompresses it. h3 is a per-request opt-in since 1.3.0.
const (
	http3NotUsed = "HTTP/3 (h3-29 or h3-27) was not used to request this page."
	http3Advert  = "it does support HTTP/3!"
)

// readBody drains the response and inflates it when the site gzipped it. The header list
// above is written by hand, so the site is free to answer with gzip, and the two paths
// differ in whether that is undone for you: the h2 transport always decompresses, the h3
// one returned the compressed bytes. Matching on the raw payload made this test fail at
// random before the flag had anything to do with it.
func readBody(t *testing.T, body io.ReadCloser) string {
	t.Helper()

	raw, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		defer zr.Close()
		plain, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("inflate: %v", err)
		}
		raw = plain
	}
	return string(raw)
}

func TestHTTP3(t *testing.T) {
	// The profile default since 1.3.0: no h3 in the ALPN list, so the site serves the
	// "not used" page.
	options := ja3.Ja3Request{
		Method:      "GET",
		URL:         "https://http3.is/",
		Impersonate: "chrome_133",
		Timeout:     30,
		Headers:     defaultHeader,
		WithDebug:   true,
		Proxy:       "http://127.0.0.1:7890",
	}

	resp, err := client.DoRequest(&options)
	if err != nil {
		t.Fatal(err)
	}

	body := readBody(t, resp.Body)
	if !strings.Contains(body, http3NotUsed) {
		t.Fatalf("page does not say the request arrived over h2:\n%s", body)
	}
}

var useHttp3 = true

func TestWithHTTP3(t *testing.T) {
	// Same request, same profile, with_http3 turned on: the server negotiates h3 out of
	// our ALPN list and answers with the success page.
	options := ja3.Ja3Request{
		Method:      "GET",
		URL:         "https://http3.is/",
		Impersonate: "chrome_133",
		Timeout:     30,
		WithHTTP3:   &useHttp3,
		WithDebug:   true,
		Headers:     defaultHeader,
		Proxy:       "http://127.0.0.1:7890",
	}

	resp, err := client.DoRequest(&options)
	if err != nil {
		t.Fatal(err)
	}

	body := readBody(t, resp.Body)
	if !strings.Contains(body, http3Advert) {
		t.Fatalf("the hello did not advertise h3:\n%s", body)
	}
}
