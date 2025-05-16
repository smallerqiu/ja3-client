package ja3_client

import (
	"bytes"
	"log"
	"strings"

	"github.com/smallerqiu/ja3-client/browser"
	"github.com/smallerqiu/ja3-client/http"
)

// 创建定制 TLS 会话
func CreateSession(request *Ja3Request) (HttpClient, *http.Request, error) {
	timeOut := request.Timeout
	if timeOut == 0 {
		timeOut = 30
	}
	jar := NewCookieJar()
	options := []HttpClientOption{
		WithTimeoutSeconds(timeOut),
		WithForceHttp1(request.ForceHTTP1),
		WithCookieJar(jar),
	}

	if !request.NotFollowRedirects {
		options = append(options, WithNotFollowRedirects())
	}

	if request.JA3String != "" {
		profile, err := FormatJa3(request.JA3String, request.Client, request.ClientVersion, false)
		if err != nil {
			return nil, nil, err
		}

		options = append(options, WithClientProfile(profile))
	} else {
		imp := request.Impersonate
		if _, ok := browser.MappedTLSClients[imp]; !ok {
			log.Printf("the input client %v dont't support", imp)
			imp = "chrome_135"
		}

		b := browser.MappedTLSClients[imp]

		options = append(options, WithClientProfile(b))
		if request.RandomExtensionOrder {
			options = append(options, WithRandomTLSExtensionOrder())
		}
	}

	// 设置代理
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

	// 设置请求头
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
