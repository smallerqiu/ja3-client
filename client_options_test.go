package ja3_client

import (
	"strings"
	"testing"

	ja3 "github.com/smallerqiu/ja3-client/ja3"

	tls "github.com/smallerqiu/utls"
)

// alpnOf reads the ALPN list out of the profile a client ended up with. It is the only
// observable that tells the three profile options apart without comparing whole specs.
func alpnOf(t *testing.T, c HttpClient) string {
	t.Helper()

	hc, ok := c.(*httpClient)
	if !ok {
		t.Fatalf("unexpected client implementation %T", c)
	}
	spec, err := hc.config.clientProfile.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("build spec: %v", err)
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*tls.ALPNExtension); ok {
			return strings.Join(alpn.AlpnProtocols, ",")
		}
	}
	t.Fatal("profile carries no ALPN extension")
	return ""
}

func uaOf(c HttpClient) string {
	return c.(*httpClient).config.clientProfile.GetUserAgent()
}

func TestImpersonateOptionSelectsProfile(t *testing.T) {
	def, err := NewHttpClient(NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	defUA := uaOf(def)

	ff, err := NewHttpClient(NewNoopLogger(), WithImpersonate("firefox_135"))
	if err != nil {
		t.Fatal(err)
	}
	viaClient, err := NewHttpClient(NewNoopLogger(), WithClient("firefox_135", nil))
	if err != nil {
		t.Fatal(err)
	}

	// The inert option used to leave the default Chrome profile in place, so both the
	// UA move and the ALPN move have to be visible here.
	if uaOf(ff) == defUA {
		t.Errorf("WithImpersonate kept the default profile: ua %q", uaOf(ff))
	}
	if uaOf(ff) != uaOf(viaClient) {
		t.Errorf("WithImpersonate and WithClient disagree: %q vs %q", uaOf(ff), uaOf(viaClient))
	}
	if got, want := alpnOf(t, ff), "h2,http/1.1"; got != want {
		t.Errorf("firefox_135 alpn = %q, want %q", got, want)
	}
	if uaOf(def) == uaOf(viaClient) {
		t.Errorf("the default profile is firefox too, so the comparison above proves nothing")
	}
}

// h3 is a property of the built spec, so the two options have to meet whichever way
// they are written.
func TestImpersonateAndHttp3OrderIndependent(t *testing.T) {
	on := true
	off := false

	for _, tc := range []struct {
		name    string
		options []HttpClientOption
		want    string
	}{
		{"impersonate then h3 on", []HttpClientOption{WithImpersonate("chrome_136"), WithHttp3(&on)}, "h3,h2,http/1.1"},
		{"h3 on then impersonate", []HttpClientOption{WithHttp3(&on), WithImpersonate("chrome_136")}, "h3,h2,http/1.1"},
		{"impersonate then h3 off", []HttpClientOption{WithImpersonate("chrome_136"), WithHttp3(&off)}, "h2,http/1.1"},
		{"h3 off then impersonate", []HttpClientOption{WithHttp3(&off), WithImpersonate("chrome_136")}, "h2,http/1.1"},
	} {
		c, err := NewHttpClient(NewNoopLogger(), tc.options...)
		if err != nil {
			t.Fatal(err)
		}
		if got := alpnOf(t, c); got != tc.want {
			t.Errorf("%s: alpn = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Last option wins, which is what a caller reading the option list top to bottom expects.
func TestProfileOptionsLastAppliedWins(t *testing.T) {
	ff, err := NewHttpClient(NewNoopLogger(), WithImpersonate("firefox_135"), WithClient("chrome_132", nil))
	if err != nil {
		t.Fatal(err)
	}
	if want := ja3.MappedTLSClients["chrome_132"].UserAgent; uaOf(ff) != want {
		t.Errorf("WithClient after WithImpersonate: ua = %q, want %q", uaOf(ff), want)
	}

	ff2, err := NewHttpClient(NewNoopLogger(), WithClient("chrome_132", nil), WithImpersonate("firefox_135"))
	if err != nil {
		t.Fatal(err)
	}
	if want := ja3.MappedTLSClients["firefox_135"].UserAgent; uaOf(ff2) != want {
		t.Errorf("WithImpersonate after WithClient: ua = %q, want %q", uaOf(ff2), want)
	}
}

// An empty id is "say nothing", not "reset to Chrome": ProvideDefaultClient and
// DefaultOptions both set a profile before the caller has a chance to name one.
func TestImpersonateEmptyKeepsProfile(t *testing.T) {
	c, err := NewHttpClient(NewNoopLogger(), WithClient("firefox_135", nil), WithImpersonate(""))
	if err != nil {
		t.Fatal(err)
	}
	if want := ja3.MappedTLSClients["firefox_135"].UserAgent; uaOf(c) != want {
		t.Errorf("empty WithImpersonate overwrote the profile: ua = %q, want %q", uaOf(c), want)
	}

	// The same rule on the other side: WithHttp3 rebuilds only a profile it knows the
	// id of. A hand-built profile has no id here, so the h3 option must leave it alone
	// rather than fall back to the default Chrome hello.
	profile, err := ja3.BuildClientHelloSpec("firefox_135", nil)
	if err != nil {
		t.Fatal(err)
	}
	on := true
	c2, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profile), WithHttp3(&on))
	if err != nil {
		t.Fatal(err)
	}
	if got := uaOf(c2); got != ja3.MappedTLSClients["firefox_135"].UserAgent {
		t.Errorf("WithHttp3 without an id replaced the profile: ua = %q", got)
	}
}
