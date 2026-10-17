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
	// TlsTrustAnchors sends the trust_anchors extension (0xca34) with an empty
	// identifier list. Chrome enables it by default from 152; earlier channels
	// only send it when the origin's HTTPS DNS record hints at trusted anchor
	// ids, which is why a plain capture of Chrome 136-151 has no 0xca34.
	TlsTrustAnchors      bool
	Client               string
	NoTlsSessionTicket   bool
	Version              string
	TlsPadding           bool
	WithHttp3            *bool
	RandomExtensionOrder bool
}
