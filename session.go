package ja3_client

import (
	"bytes"
	"net"
	"strings"

	"github.com/smallerqiu/ja3-client/http"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func CreateSession(request *ja3.Ja3Request) (HttpClient, error) {
	timeout := request.Timeout
	if timeout == 0 {
		timeout = 30
	}
	jar := NewCookieJar()
	options := []HttpClientOption{
		WithTimeoutSeconds(timeout),
		WithForceHttp1(request.ForceHTTP1),
		WithCookieJar(jar),
	}
	if request.WithHTTP3 != nil {
		options = append(options, WithHttp3(request.WithHTTP3))
	}
	if request.WithDebug {
		options = append(options, WithDebug())
	}
	// NotFollowRedirects opts out of the default, which is to follow redirects the
	// way net/http does. This used to read `if !request.NotFollowRedirects`, which
	// inverted it: leaving the field alone disabled following, and setting it to
	// true enabled it.
	if request.NotFollowRedirects {
		options = append(options, WithNotFollowRedirects())
	}
	// Seeds the UA for the branches that cannot resolve one from a profile
	// (empty GetUserAgent). Read from DefaultClient so it follows
	// ja3.DefaultImpersonate instead of drifting behind it.
	userAgent := ja3.DefaultClient.UserAgent

	if request.Ja3 != "" {
		profile, err := ja3.BuildClientHelloSpecFromJa3Key(request.Ja3, request.Akamai, request.WithHTTP3)
		if err != nil {
			return nil, err
		}
		options = append(options, WithClientProfile(profile))
		if profile.GetUserAgent() != "" {
			userAgent = profile.GetUserAgent()
		}
	} else if request.ClientData != nil {
		profile, err := ja3.BuildClientHelloSpecWithCP(*request.ClientData)
		if err != nil {
			return nil, err
		}
		options = append(options, WithClientProfile(profile))
		if profile.GetUserAgent() != "" {
			userAgent = profile.GetUserAgent()
		}
	} else {
		impersonate := ja3.DefaultImpersonate
		if request.Impersonate != "" {
			impersonate = request.Impersonate
		}
		profile, err := ja3.BuildClientHelloSpec(impersonate, request.WithHTTP3)
		if err != nil {
			return nil, err
		}
		options = append(options, WithClientProfile(profile))
		if request.RandomExtensionOrder {
			options = append(options, WithRandomTLSExtensionOrder())
		}
		if profile.GetUserAgent() != "" {
			userAgent = profile.GetUserAgent()
		}
	}

	if request.Proxy != "" {
		options = append(options, WithProxyUrl(request.Proxy))
	}

	if request.SourceIP != "" {
		options = append(options, WithLocalAddr(net.TCPAddr{IP: net.ParseIP(request.SourceIP), Port: 0}))
	}

	var header = http.Header{}
	header.Set("user-agent", userAgent)

	if request.Headers != nil {
		for k, v := range request.Headers {
			header.Set(k, strings.Join(v, ", "))
		}

		// The transport does not decompress everything on every protocol: HTTP/2
		// always does (http/h2_bundle.go calls DecompressBody), HTTP/1 only for
		// gzip, HTTP/3 for the gzip it injects itself. So a request that asks for
		// br on HTTP/1 would get compressed bytes back. Pinning identity is the
		// safe default - but only when the caller did not choose, because a caller
		// who wrote `accept-encoding: gzip, deflate, br, zstd` to look like Chrome
		// had it silently replaced by identity, which is the one header no browser
		// sends.
		if header.Get("accept-encoding") == "" {
			header.Set("accept-encoding", "identity")
		}
	}

	options = append(options, WithDefaultHeaders(header))

	client, err := NewHttpClient(NewNoopLogger(), options...)

	if err != nil {
		return nil, err
	}

	return client, nil
}

func DoRequest(request *ja3.Ja3Request) (*http.Response, error) {
	client, err := CreateSession(request)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequest(request.Method, request.URL, bytes.NewReader(request.Body))
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return res, err
}

func buildRequest(method string, url string, headers http.Header, body []byte) (req *ja3.Ja3Request) {
	return &ja3.Ja3Request{
		Method:      method,
		URL:         url,
		Headers:     headers,
		Body:        body,
		Impersonate: ja3.DefaultImpersonate,
	}
}

func Get(url string, headers http.Header) (*http.Response, error) {
	return DoRequest(buildRequest(http.MethodGet, url, headers, nil))
}
func Post(url string, body []byte, headers http.Header) (*http.Response, error) {
	return DoRequest(buildRequest(http.MethodPost, url, headers, body))
}
func Put(url string, body []byte, headers http.Header) (*http.Response, error) {
	return DoRequest(buildRequest(http.MethodPut, url, headers, body))
}

func Delete(url string, headers http.Header) (*http.Response, error) {
	return DoRequest(buildRequest(http.MethodDelete, url, headers, nil))
}
