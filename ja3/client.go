package ja3

import "github.com/smallerqiu/ja3-client/http2"

type CandidateCipherSuites struct {
	KdfId  string
	AeadId string
}

type ClientData struct {
	CipherSuites            string
	Curves                  string
	SignatureHashed         string
	Http2Setting            string
	Http2WindowUpdate       uint32
	Http2StreamWight        int
	Http2StreamDep          int
	Http2StreamExclusive    int
	Http2PseudoHeaderOrder  string
	Http2Priorities         string
	Compressed              bool
	TlsExtensionOrder       string
	TlsDelegatedCredentials string
	TlsRecordSizeLimit      int
	TlsKeySharesLimit       int // default 3
	TlsVersion              string
	TlsGrease               bool
	Ech                     bool
	ALPS                    bool
	ALPSO                   bool
	ALPSS                   bool
	CertCompression         string
	Client                  string
	Version                 string
	TlsPadding              bool
	RandomExtensionOrder    bool
}

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
	tlsVersion                              string
}
