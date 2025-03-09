package ja3_client

import "github.com/smallerqiu/ja3-client/http2"

type ProfileData struct {
	connectionFlow                          uint32
	settingsOrder                           []http2.SettingID
	settings                                map[http2.SettingID]uint32
	supportedSignatureAlgorithms            []string
	supportedDelegatedCredentialsAlgorithms []string
	supportedVersions                       []string
	keyShareCurves                          []string
	supportedProtocolsALPN                  []string
	supportedProtocolsALPS                  []string
	candidatePayloads                       []uint16
	pseudoHeaderOrder                       []string
	priorities                              []http2.Priority
	headerPriority                          *http2.PriorityParam
	certCompressionAlgo                     string
	echCandidateCipherSuites                []CandidateCipherSuites
}

type Ja3Request struct {
	Method               string
	URL                  string
	Headers              map[string][]string
	Proxy                string
	Impersonate          string
	JA3String            string
	Client               string
	ClientVersion        string
	ForceHTTP1           bool
	Body                 []byte
	RandomExtensionOrder bool
	Timeout              int // default 30s
	NotFollowRedirects   bool
}

type Response struct {
	StatusCode int
	Headers    map[string][]string
	Cookies    map[string]string
	Body       string
}
