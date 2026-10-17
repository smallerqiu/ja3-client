package ja3_client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	patchedhttp "github.com/smallerqiu/ja3-client/http"
	"github.com/smallerqiu/ja3-client/ja3"
)

// echoHeaders answers with the request headers it received, so a test can assert
// what actually went on the wire instead of what the option list was supposed to
// hold.
func echoHeaders(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]http.Header{"headers": r.Header})
	}))
	t.Cleanup(server.Close)

	return server
}

func readEcho(t *testing.T, res *patchedhttp.Response) http.Header {
	t.Helper()

	defer res.Body.Close()

	var got struct {
		Headers http.Header `json:"headers"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("decode echo: %v", err)
	}

	return got.Headers
}

// TestDoRequestKeepsCallerAcceptEncoding covers the header a caller is most likely
// to set on purpose: a browser-like accept-encoding. Forcing identity over it made
// every impersonated request send the one value no browser sends.
func TestDoRequestKeepsCallerAcceptEncoding(t *testing.T) {
	server := echoHeaders(t)

	const browserValue = "gzip, deflate, br, zstd"

	res, err := DoRequest(&ja3.Ja3Request{
		Method: http.MethodGet,
		URL:    server.URL,
		Headers: http.Header{
			"accept-encoding": []string{browserValue},
			"accept":          []string{"text/html"},
		},
	})
	if err != nil {
		t.Fatalf("DoRequest: %v", err)
	}

	if got := readEcho(t, res).Get("Accept-Encoding"); got != browserValue {
		t.Errorf("accept-encoding = %q, want the caller's %q", got, browserValue)
	}
}

// TestDoRequestPinsIdentityWhenUnset keeps the protection itself: with no choice
// from the caller, the response body has to arrive readable, because the HTTP/1
// transport only decompresses gzip.
func TestDoRequestPinsIdentityWhenUnset(t *testing.T) {
	server := echoHeaders(t)

	res, err := DoRequest(&ja3.Ja3Request{
		Method:  http.MethodGet,
		URL:     server.URL,
		Headers: http.Header{"accept": []string{"text/html"}},
	})
	if err != nil {
		t.Fatalf("DoRequest: %v", err)
	}

	if got := readEcho(t, res).Get("Accept-Encoding"); got != "identity" {
		t.Errorf("accept-encoding = %q, want the default identity", got)
	}
}

// TestDoRequestWithoutHeadersSaysNothing documents the other branch: with no
// Headers the profile's default header set is used and nothing is pinned here.
func TestDoRequestWithoutHeadersSaysNothing(t *testing.T) {
	server := echoHeaders(t)

	res, err := DoRequest(&ja3.Ja3Request{Method: http.MethodGet, URL: server.URL})
	if err != nil {
		t.Fatalf("DoRequest: %v", err)
	}

	got := readEcho(t, res).Get("Accept-Encoding")
	if got == "identity" {
		t.Errorf("a request without Headers was pinned to identity; it sent %q", got)
	}
	t.Logf("no Headers -> accept-encoding on the wire: %q", got)
}

// TestCustomClientDataRejectsOversizedStreamWeight pins the guard that replaces
// the old uint8() truncation: a weight that does not fit the priority byte has to
// fail loudly instead of silently declaring the lightest stream in HTTP/2.
func TestCustomClientDataRejectsOversizedStreamWeight(t *testing.T) {
	_, err := ja3.BuildClientHelloSpecWithCP(ja3.ClientData{
		UserAgent:    "Mozilla/5.0",
		Client:       "chrome",
		Version:      "1",
		CipherSuites: "TLS_AES_128_GCM_SHA256",
		// Three curves because the key share limit defaults to 3; a profile whose
		// limit exceeds its curve list fails earlier for a different reason.
		Curves:               "X25519:P256:P384",
		Http2Setting:         "1:65536",
		Http2WindowUpdate:    1,
		Http2StreamWight:     256,
		Http2StreamExclusive: 1,
		TlsVersion:           "1.3",
	})
	if err == nil {
		t.Fatal("Http2StreamWight: 256 built a profile; it must be rejected")
	}
	if !strings.Contains(err.Error(), "does not fit the priority weight byte") {
		t.Fatalf("wrong rejection reason: %v", err)
	}
}
