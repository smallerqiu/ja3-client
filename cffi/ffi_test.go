package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	client "github.com/smallerqiu/ja3-client"
	patchedhttp "github.com/smallerqiu/ja3-client/http"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

// These tests cover the FFI contract itself: key spelling, header layering, body
// encoding and the handle table. Nothing here needs internet access - the request
// tests run against httptest servers, because a fingerprint library whose bindings
// can only be tried against example.com is a binding nobody can test in CI.

func decodeEnvelope(t *testing.T, raw string) map[string]any {
	t.Helper()

	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("envelope is not JSON: %v\n%s", err, raw)
	}

	return out
}

func TestNormalizeIntoAcceptsEveryKeySpelling(t *testing.T) {
	cases := []struct {
		name  string
		json  string
		check func(*ffiRequest) bool
	}{
		{"snake_case", `{"with_http3":false,"force_http1":true,"random_extension_order":true}`,
			func(r *ffiRequest) bool {
				return r.WithHTTP3 != nil && !*r.WithHTTP3 && r.ForceHTTP1 && r.RandomExtensionOrder
			}},
		{"Go field names", `{"WithHTTP3":true,"ForceHTTP1":true,"SourceIP":"10.0.0.1"}`,
			func(r *ffiRequest) bool {
				return r.WithHTTP3 != nil && *r.WithHTTP3 && r.ForceHTTP1 && r.SourceIP == "10.0.0.1"
			}},
		{"kebab-case", `{"not-follow-redirects":true}`,
			func(r *ffiRequest) bool { return r.NotFollowRedirects }},
		{"client_data snake_case", `{"client_data":{"cipher_suites":"1,2","http_2_setting":"1:65536"}}`,
			func(r *ffiRequest) bool {
				return r.ClientData != nil && r.ClientData.Data.CipherSuites == "1,2" &&
					r.ClientData.Data.Http2Setting == "1:65536"
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, bad := parseRequest(tc.json)
			if bad != nil {
				t.Fatalf("parse failed: %s", bad.Error)
			}

			if !tc.check(req) {
				t.Fatalf("option did not land: parsed=%+v", *req)
			}
		})
	}
}

func TestParseRequestReportsUnknownKeys(t *testing.T) {
	// A typo behind a C ABI is otherwise invisible: the caller just gets default
	// behaviour with no signal at all.
	req, bad := parseRequest(`{"url":"https://example.com","with_http4":true,"impersonate":"chrome_133"}`)
	if bad != nil {
		t.Fatalf("parse failed: %s", bad.Error)
	}

	if len(req.warnings) != 1 || !strings.Contains(req.warnings[0], "with_http4") {
		t.Fatalf("want a warning about with_http4, got %#v", req.warnings)
	}
}

func TestParseRequestRejectsMalformedJSON(t *testing.T) {
	if _, bad := parseRequest(`{"url":`); bad == nil || bad.ErrorCode != ErrBadJSON {
		t.Fatalf("want ErrBadJSON, got %#v", bad)
	}
}

func TestHeaderOps(t *testing.T) {
	ops, warnings := parseHeaderOps(map[string]any{
		"accept-encoding": nil, // removal
		"x-multi":         []any{"a", "b"},
		"x-empty":         []any{},     // also removal
		"x-number":        float64(42), // other languages send numbers
		"x-bad-list":      []any{nil},  // warned and dropped
	})
	if !strings.Contains(strings.Join(warnings, "|"), "no usable list values") {
		t.Fatalf("want a warning about the unusable list, got %#v", warnings)
	}

	header := applyHeaderOps(nil, ops)

	if got := header.Get("X-Multi"); got != "a" {
		t.Fatalf("multi-value header should keep both entries, Get=%q values=%v", got, header.Values("X-Multi"))
	}

	if len(header.Values("X-Multi")) != 2 {
		t.Fatalf("want 2 values on x-multi, got %v", header.Values("X-Multi"))
	}

	if len(header.Values("X-Empty")) != 0 || len(header.Values("Accept-Encoding")) != 0 {
		t.Fatalf("removals did not take: %#v", map[string][]string(header))
	}

	if header.Get("X-Number") != "42" {
		t.Fatalf("numeric header: %q", header.Get("X-Number"))
	}
}

func TestApplyHeaderOpsOverridesCaseInsensitively(t *testing.T) {
	// The base uses the canonical spelling the library writes; a caller sending
	// "user-agent" must replace it, not add a second one.
	base := applyHeaderOps(nil, []headerOp{{name: "User-Agent", values: []string{"profile"}}})
	merged := applyHeaderOps(base, []headerOp{{name: "user-agent", values: []string{"mine"}}})

	if len(merged.Values("User-Agent")) != 1 || merged.Get("User-Agent") != "mine" {
		t.Fatalf("want one overridden user-agent, got %#v", map[string][]string(merged))
	}

	if merged.Get("user-agent") != "mine" {
		t.Fatalf("lookup must stay case-insensitive")
	}
}

func TestRequestBodyEncoding(t *testing.T) {
	req := &ffiRequest{Body: "héllo"}
	body, err := req.bodyBytes()
	if err != nil || string(body) != "héllo" {
		t.Fatalf("utf-8 body: %q %v", body, err)
	}

	raw := "\x00\x01\x02binary"
	req = &ffiRequest{BodyBase64: base64.StdEncoding.EncodeToString([]byte(raw))}
	body, err = req.bodyBytes()
	if err != nil || string(body) != raw {
		t.Fatalf("base64 body: %q %v", body, err)
	}

	if _, err := (&ffiRequest{BodyBase64: "!!!"}).bodyBytes(); err == nil {
		t.Fatal("invalid base64 must be an error")
	}
}

func TestFillResponseSplitsTextAndBinary(t *testing.T) {
	env := okEnvelope()
	resp := &patchedhttp.Response{StatusCode: 200, Proto: "HTTP/2.0", Header: patchedhttp.Header{}}

	fillResponse(env, resp, []byte("plain text"))
	if env.Body != "plain text" || env.BodyBinary || env.BodySize != len("plain text") {
		t.Fatalf("text body: %#v", env)
	}

	env = okEnvelope()
	fillResponse(env, resp, []byte{0xff, 0xfe, 0x00})
	if env.Body != "" || !env.BodyBinary || env.BodyBase64 == "" {
		t.Fatalf("binary body must go through base64: %#v", env)
	}

	decoded, err := base64.StdEncoding.DecodeString(env.BodyBase64)
	if err != nil || len(decoded) != 3 {
		t.Fatalf("base64 round trip: %v", err)
	}
}

func TestVersionEnvelopeCarriesAbi(t *testing.T) {
	env := decodeEnvelope(t, (&ffiResponse{ErrorCode: ErrOK, OK: true, Version: "1.2.4", Abi: ABIVersion}).encode())

	if env["abi"] != float64(ABIVersion) {
		t.Fatalf("abi missing: %#v", env)
	}
}

// newTestServer serves JSON and records the headers it received.
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server
}

func TestSessionRequestKeepsProfileHeaders(t *testing.T) {
	var got http.Header

	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	req, bad := parseRequest(`{"url":"` + server.URL + `"}`)
	if bad != nil {
		t.Fatalf("parse: %s", bad.Error)
	}

	s, err := buildSession(req)
	if err != nil {
		t.Fatalf("buildSession: %v", err)
	}
	defer s.handle.CloseIdleConnections()

	env, err := s.perform(req)
	if err != nil {
		t.Fatalf("perform: %v", err)
	}

	if env.StatusCode != http.StatusOK {
		t.Fatalf("status %d", env.StatusCode)
	}

	// A request without its own headers must still look like the impersonated
	// browser, not like Go.
	if ua := got.Get("User-Agent"); ua == "" || strings.HasPrefix(ua, "Go-http-client") {
		t.Fatalf("profile user-agent lost: %q", ua)
	}

	if ae := got.Get("Accept-Encoding"); ae != "identity" {
		t.Fatalf("accept-encoding should default to identity so the body is readable, got %q", ae)
	}
}

func TestSessionRequestMergesPerCallHeaders(t *testing.T) {
	var got http.Header

	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte("ok"))
	})

	sessionReq, _ := parseRequest(`{"url":"` + server.URL + `","impersonate":"chrome_133"}`)

	s, err := buildSession(sessionReq)
	if err != nil {
		t.Fatalf("buildSession: %v", err)
	}
	defer s.handle.CloseIdleConnections()

	callReq, bad := parseRequest(`{"url":"` + server.URL + `","headers":{"x-demo":["1","2"],"accept-encoding":"gzip, br","user-agent":null}}`)
	if bad != nil {
		t.Fatalf("parse: %s", bad.Error)
	}

	env, err := s.perform(callReq)
	if err != nil {
		t.Fatalf("perform: %v", err)
	}

	if len(env.Warnings) == 0 || !strings.Contains(env.Warnings[0], "user-agent") {
		t.Fatalf("removing a session default should be reported: %#v", env.Warnings)
	}

	if got.Get("X-Demo") != "1" || len(got.Values("X-Demo")) != 2 {
		t.Fatalf("multi-value header not forwarded: %#v", map[string][]string(got))
	}

	if got.Get("Accept-Encoding") != "gzip, br" {
		t.Fatalf("caller accept-encoding must win over the identity default: %q", got.Get("Accept-Encoding"))
	}

	// Removing the profile user-agent leaves net/http's own default, which proves
	// the header really was deleted rather than ignored.
	if ua := got.Get("User-Agent"); strings.Contains(ua, "Chrome") {
		t.Fatalf("user-agent removal failed: %q", ua)
	}
}

func TestSessionHandleTable(t *testing.T) {
	t.Parallel()

	var received []string

	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/issue" {
			http.SetCookie(w, &http.Cookie{Name: "seen", Value: "yes", Path: "/"})
		}

		received = append(received, r.Header.Get("Cookie"))
		_, _ = w.Write([]byte(r.URL.Path))
	})

	issueReq, _ := parseRequest(`{"url":"` + server.URL + `/issue"}`)
	checkReq, _ := parseRequest(`{"url":"` + server.URL + `/check"}`)

	s, err := buildSession(issueReq)
	if err != nil {
		t.Fatalf("buildSession: %v", err)
	}

	id := registerSession(s)
	if id == 0 {
		t.Fatal("handle must be non-zero")
	}

	if lookupSession(id) != s {
		t.Fatal("lookup must return the registered session")
	}

	if _, err := s.perform(issueReq); err != nil {
		t.Fatalf("first perform: %v", err)
	}

	env, err := lookupSession(id).perform(checkReq)
	if err != nil {
		t.Fatalf("second perform: %v", err)
	}

	if env.Body != "/check" {
		t.Fatalf("body: %q", env.Body)
	}

	if env.Session != 0 {
		t.Fatalf("perform does not stamp the handle; the export does: %d", env.Session)
	}

	if len(received) != 2 || !strings.Contains(received[1], "seen=yes") {
		t.Fatalf("cookie jar is not shared across requests on one handle: %#v", received)
	}

	if !closeSession(id) {
		t.Fatal("first close must report the handle was open")
	}

	if closeSession(id) {
		t.Fatal("second close must report the handle is gone")
	}

	if lookupSession(id) != nil {
		t.Fatal("closed handle must not resolve")
	}

	if lookupSession(0) != nil {
		t.Fatal("handle 0 must never resolve")
	}
}

func TestRedirectDefaultFollows(t *testing.T) {
	// session.go used to read `if !request.NotFollowRedirects`, which made the
	// default refuse redirects and opting out enable them.
	var hits int

	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++

		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)

			return
		}

		_, _ = w.Write([]byte("final"))
	})

	req, _ := parseRequest(`{"url":"` + server.URL + `/start"}`)
	env, err := doOneShot(req)
	if err != nil {
		t.Fatalf("doOneShot: %v", err)
	}

	if hits != 2 || env.Body != "final" {
		t.Fatalf("default must follow redirects: hits=%d body=%q", hits, env.Body)
	}

	optOut, _ := parseRequest(`{"url":"` + server.URL + `/start","not_follow_redirects":true}`)
	env, err = doOneShot(optOut)
	if err != nil {
		t.Fatalf("doOneShot opt-out: %v", err)
	}

	if env.StatusCode != http.StatusFound {
		t.Fatalf("not_follow_redirects must stop at the 302: %d", env.StatusCode)
	}
}

func TestOneShotRequestErrorCarriesCode(t *testing.T) {
	// Port 1 is closed; the transport error must surface as a code, not an empty body.
	req, _ := parseRequest(`{"url":"http://127.0.0.1:1/nope","timeout":2}`)

	env, err := doOneShot(req)
	if err == nil {
		t.Fatalf("want a transport error, got %#v", env)
	}

	out := envelopeFor(err)
	if out.ErrorCode != ErrRequest || out.OK {
		t.Fatalf("want ErrRequest, got %#v", out)
	}

	if strings.Contains(out.encode(), `"body":""`) {
		t.Fatal("empty fields should be omitted, not emitted as empty strings")
	}
}

func TestDoRequestDefaultMatchesFFI(t *testing.T) {
	// The exported client.DoRequest and ja3_request have to agree about redirects,
	// otherwise bindings and Go callers see two different libraries.
	var hits int

	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++

		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)

			return
		}

		_, _ = w.Write([]byte("final"))
	})

	resp, err := client.DoRequest(&ja3.Ja3Request{
		Method:      "GET",
		URL:         server.URL + "/start",
		Impersonate: "chrome_133",
	})
	if err != nil {
		t.Fatalf("DoRequest: %v", err)
	}
	defer resp.Body.Close()

	if hits != 2 {
		t.Fatalf("DoRequest default diverged from the FFI: hits=%d", hits)
	}
}
