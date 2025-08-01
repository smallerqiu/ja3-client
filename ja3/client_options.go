package ja3

import (
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/smallerqiu/ja3-client/http"
	"golang.org/x/net/proxy"
)

type HttpClientOption func(config *httpClientConfig)

type TransportOptions struct {
	// KeyLogWriter is an io.Writer that the TLS client will use to write the
	// TLS master secrets to. This can be used to decrypt TLS connections in
	// Wireshark and other applications.
	KeyLogWriter io.Writer
	// IdleConnTimeout is the maximum amount of time an idle (keep-alive)
	// connection will remain idle before closing itself. Zero means no limit.
	IdleConnTimeout *time.Duration
	// RootCAs is the set of root certificate authorities used to verify
	// the remote server's certificate.
	RootCAs                *x509.CertPool
	MaxIdleConns           int
	MaxIdleConnsPerHost    int
	MaxConnsPerHost        int
	MaxResponseHeaderBytes int64 // Zero means to use a default limit.
	WriteBufferSize        int   // If zero, a default (currently 4KB) is used.
	ReadBufferSize         int   // If zero, a default (currently 4KB) is used.
	DisableKeepAlives      bool
	DisableCompression     bool
}

type BadPinHandlerFunc func(req *http.Request)
type ProxyDialerFactory func(proxyUrlStr string, timeout time.Duration, localAddr *net.TCPAddr, connectHeaders http.Header) (proxy.ContextDialer, error)

type httpClientConfig struct {
	cookieJar          http.CookieJar
	customRedirectFunc func(req *http.Request, via []*http.Request) error
	certificatePins    map[string][]string
	defaultHeaders     http.Header
	connectHeaders     http.Header
	badPinHandler      BadPinHandlerFunc
	transportOptions   *TransportOptions
	localAddr          *net.TCPAddr

	dialer             net.Dialer
	proxyDialerFactory ProxyDialerFactory

	proxyUrl                    string
	serverNameOverwrite         string
	clientProfile               ClientProfile
	timeout                     time.Duration
	catchPanics                 bool
	debug                       bool
	followRedirects             bool
	insecureSkipVerify          bool
	withRandomTlsExtensionOrder bool
	forceHttp1                  bool

	// Establish a connection to origin server via ipv4 only
	disableIPV6 bool
	// Establish a connection to origin server via ipv6 only
	disableIPV4 bool

	enabledBandwidthTracker bool
}

// WithProxyUrl configures a HTTP client to use the specified proxy URL.
//
// proxyUrl should be formatted as:
//
//	"http://user:pass@host:port"
func WithProxyUrl(proxyUrl string) HttpClientOption {
	return func(config *httpClientConfig) {
		config.proxyUrl = proxyUrl
	}
}

// WithCharlesProxy configures the HTTP client to use a local running charles as proxy.
//
// host and port can be empty, then default 127.0.0.1 and port 8888 will be used
func WithCharlesProxy(host string, port string) HttpClientOption {
	h := "127.0.0.1"
	p := "8888"

	if host != "" {
		h = host
	}

	if port != "" {
		p = port
	}

	proxyUrl := fmt.Sprintf("http://%s:%s", h, p)

	return WithProxyUrl(proxyUrl)
}

// WithCookieJar configures a HTTP client to use the specified cookie jar.
func WithCookieJar(jar http.CookieJar) HttpClientOption {
	return func(config *httpClientConfig) {
		config.cookieJar = jar
	}
}

// WithTimeoutMilliseconds configures an HTTP client to use the specified request timeout.
//
// timeout is the request timeout in milliseconds.
func WithTimeoutMilliseconds(timeout int) HttpClientOption {
	return func(config *httpClientConfig) {
		config.timeout = time.Millisecond * time.Duration(timeout)
	}
}

// WithDialer configures an HTTP client to use the specified dialer. This allows the use of a custom DNS resolver
func WithDialer(dialer net.Dialer) HttpClientOption {
	return func(config *httpClientConfig) {
		config.dialer = dialer
	}
}

// WithProxyDialerFactory configures an HTTP client to use a custom proxyDialerFactory instead of newConnectDialer(). This allows to implement custom proxy dialer use cases
func WithProxyDialerFactory(proxyDialerFactory ProxyDialerFactory) HttpClientOption {
	return func(config *httpClientConfig) {
		config.proxyDialerFactory = proxyDialerFactory
	}
}

// WithTimeoutSeconds configures an HTTP client to use the specified request timeout.
//
// timeout is the request timeout in seconds.
func WithTimeoutSeconds(timeout int) HttpClientOption {
	return func(config *httpClientConfig) {
		config.timeout = time.Second * time.Duration(timeout)
	}
}

// WithTimeout configures an HTTP client to use the specified request timeout.
//
// timeout is the request timeout in seconds.
// Deprecated: use either WithTimeoutSeconds or WithTimeoutMilliseconds
func WithTimeout(timeout int) HttpClientOption {
	return func(config *httpClientConfig) {
		config.timeout = time.Second * time.Duration(timeout)
	}
}

// WithNotFollowRedirects configures an HTTP client to not follow HTTP redirects.
func WithNotFollowRedirects() HttpClientOption {
	return func(config *httpClientConfig) {
		config.followRedirects = false
	}
}

// WithLocalAddr configures an HTTP client to use the specified local address.
func WithLocalAddr(localAddr net.TCPAddr) HttpClientOption {
	return func(config *httpClientConfig) {
		config.localAddr = &localAddr
	}
}

// WithCustomRedirectFunc configures an HTTP client to use a custom redirect func.
// The redirect func have to look like that: func(req *http.Request, via []*http.Request) error
// Please only provide a custom redirect function if you know what you are doing.
// Check docs on net/http.Client CheckRedirect
func WithCustomRedirectFunc(redirectFunc func(req *http.Request, via []*http.Request) error) HttpClientOption {
	return func(config *httpClientConfig) {
		config.customRedirectFunc = redirectFunc
	}
}

// WithRandomTLSExtensionOrder configures a TLS client to randomize the order of TLS extensions being sent in the ClientHello.
//
// Placement of GREASE and padding is fixed and will not be affected by this.
func WithRandomTLSExtensionOrder() HttpClientOption {
	return func(config *httpClientConfig) {
		config.withRandomTlsExtensionOrder = true
	}
}

// WithCertificatePinning enables SSL Pinning for the client and will throw an error if the SSL Pin is not matched.
// Please refer to https://github.com/tam7t/hpkp/#examples in order to see how to generate pins. The certificatePins are a map with the host as key.
// You can provide a BadPinHandlerFunc or nil as second argument. This function will be executed once a bad ssl pin is detected.
// BadPinHandlerFunc has to be defined like this: func(req *http.Request){}
func WithCertificatePinning(certificatePins map[string][]string, handlerFunc BadPinHandlerFunc) HttpClientOption {
	return func(config *httpClientConfig) {
		config.certificatePins = certificatePins
		config.badPinHandler = handlerFunc
	}
}

// WithDebug configures a client to log debugging information.
func WithDebug() HttpClientOption {
	return func(config *httpClientConfig) {
		config.debug = true
	}
}

// WithCatchPanics configures a client to catch all go panics happening during a request and not print the stacktrace.
func WithCatchPanics() HttpClientOption {
	return func(config *httpClientConfig) {
		config.catchPanics = true
	}
}

// WithTransportOptions configures a client to use the specified transport options.
func WithTransportOptions(transportOptions *TransportOptions) HttpClientOption {
	return func(config *httpClientConfig) {
		config.transportOptions = transportOptions
	}
}

// WithInsecureSkipVerify configures a client to skip SSL certificate verification.
func WithInsecureSkipVerify() HttpClientOption {
	return func(config *httpClientConfig) {
		config.insecureSkipVerify = true
	}
}

// WithForceHttp1 configures a client to force HTTP/1.1 as the used protocol.
func WithForceHttp1(forceHttp1 bool) HttpClientOption {
	return func(config *httpClientConfig) {
		config.forceHttp1 = forceHttp1
	}
}

// WithClientProfile configures a TLS client to use the specified client profile.
func WithClientProfile(clientProfile ClientProfile) HttpClientOption {
	return func(config *httpClientConfig) {
		config.clientProfile = clientProfile
	}
}

// WithDefaultHeaders configures a TLS client to use a set of default headers if none are specified on the request.
func WithDefaultHeaders(defaultHeaders http.Header) HttpClientOption {
	return func(config *httpClientConfig) {
		config.defaultHeaders = defaultHeaders
	}
}

// WithServerNameOverwrite configures a TLS client to overwrite the server name being used for certificate verification and in the client hello.
// This option does only work properly if WithInsecureSkipVerify is set to true in addition
func WithServerNameOverwrite(serverName string) HttpClientOption {
	return func(config *httpClientConfig) {
		config.serverNameOverwrite = serverName
	}
}

// WithDisableIPV6 configures a dialer to use tcp4 network argument
func WithDisableIPV6() HttpClientOption {
	return func(config *httpClientConfig) {
		config.disableIPV6 = true
	}
}

// WithDisableIPV4 configures a dialer to use tcp6 network argument
func WithDisableIPV4() HttpClientOption {
	return func(config *httpClientConfig) {
		config.disableIPV4 = true
	}
}

// WithBandwidthTracker configures a client to track the bandwidth used by the client.
func WithBandwidthTracker() HttpClientOption {
	return func(config *httpClientConfig) {
		config.enabledBandwidthTracker = true
	}
}

// WithConnectHeaders configures a client to use the specified headers for the CONNECT request.
func WithConnectHeaders(headers http.Header) HttpClientOption {
	return func(config *httpClientConfig) {
		config.connectHeaders = headers
	}
}
