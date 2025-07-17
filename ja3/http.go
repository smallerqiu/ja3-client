package ja3

type Ja3Request struct {
	Method               string
	URL                  string
	Headers              map[string][]string
	Proxy                string
	Impersonate          string
	Ja3                  string
	Akamai               string
	Client               string
	ClientVersion        string
	ForceHTTP1           bool
	Body                 []byte
	RandomExtensionOrder bool
	Timeout              int // default 30s
	NotFollowRedirects   bool
	ClientData           *ClientData
}

type Response struct {
	StatusCode int
	Headers    map[string][]string
	Cookies    map[string]string
	Body       string
}
