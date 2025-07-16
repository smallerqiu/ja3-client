package ja3_client

import (
	"bytes"
	"strings"

	"github.com/smallerqiu/ja3-client/http"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func CreateSession(request *ja3.Ja3Request) (HttpClient, *http.Request, error) {
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

	if !request.NotFollowRedirects {
		options = append(options, WithNotFollowRedirects())
	}
	userAgent := ""
	if request.Ja3 != "" {
		profile, err := ja3.BuildClientHelloSpecFromJa3Key(request.Ja3, request.Akamai)
		if err != nil {
			return nil, nil, err
		}

		options = append(options, WithClientProfile(profile))
		userAgent = profile.GetUserAgent()
	} else {
		impersonate := request.Impersonate

		profile, err := ja3.BuildClientHelloSpec(impersonate)
		if err != nil {
			return nil, nil, err
		}
		userAgent = profile.GetUserAgent()
		options = append(options, WithClientProfile(profile))
		if request.RandomExtensionOrder {
			options = append(options, WithRandomTLSExtensionOrder())
		}
	}

	if request.Proxy != "" {
		options = append(options, WithProxyUrl(request.Proxy))
	}

	client, err := NewHttpClient(NewNoopLogger(), options...)

	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest(request.Method, request.URL, bytes.NewReader(request.Body))

	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("user-agent", userAgent)

	if request.Headers != nil {
		if req.Header == nil {
			req.Header = make(map[string][]string)
		}
		for k, v := range request.Headers {
			req.Header.Set(k, strings.Join(v, ", "))
		}
		req.Header.Set("accept-encoding", "identity")
	}

	return client, req, nil
}
