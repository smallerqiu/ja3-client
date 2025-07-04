package ja3_client

import (
	"bytes"
	"log"
	"strings"

	"github.com/smallerqiu/ja3-client/http"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

// 创建定制 TLS 会话
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

	if request.JA3String != "" {
		profile, err := ja3.FormatJa3(request.JA3String, request.Client, request.ClientVersion, false)
		if err != nil {
			return nil, nil, err
		}

		options = append(options, WithClientProfile(profile))
	} else {
		imp := request.Impersonate
		if _, ok := MappedTLSClients[request.Impersonate]; !ok {
			log.Printf("the input client %v dont't support, so use default chrome 137", imp)
			imp = "chrome_137"
		}

		b := MappedTLSClients[imp]

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
