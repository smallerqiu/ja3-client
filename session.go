package ja3_client

import (
	"bytes"
	"strings"

	http "github.com/smallerqiu/fhttp"
	browser "github.com/smallerqiu/utls/browser"
)

// 创建定制 TLS 会话
func CreateSession(request *Ja3Request) (HttpClient, *http.Request, error) {

	jar := NewCookieJar()
	options := []HttpClientOption{
		WithTimeoutSeconds(30),
		WithNotFollowRedirects(),
		WithForceHttp1(false),
		WithCookieJar(jar),
	}

	// 解析 JA3 指纹
	if b, ok := browser.MappedTLSClients[request.Impersonate]; ok {
		options = append(options, WithClientProfile(b))

	} else if request.JA3String != "" {
		profile, err := FormatJa3(request.JA3String, request.Client, request.ClientVersion)
		if err != nil {
			return nil, nil, err
		}

		options = append(options, WithClientProfile(profile))
	} else {
		// default chrome 133
		options = append(options, WithClientProfile(browser.Chrome_133))
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
