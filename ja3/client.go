package ja3

type CandidateCipherSuites struct {
	KdfId  string
	AeadId string
}

type ClientData struct {
	CipherSuites            string
	Curves                  string
	SignatureHashed         string
	UserAgent               string
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
	NoTlsSessionTicket      bool
	Version                 string
	TlsPadding              bool
	RandomExtensionOrder    bool
}
