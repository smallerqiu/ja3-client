package ja3

var withHttp3 = true

// Chrome 142 through 149 send Chrome_136's ClientHello and HTTP/2 frames
// unchanged: same cipher suites, same sixteen extensions, same groups, key shares
// and signature algorithms, same settings and window update. Only the User-Agent
// and the header list move, and the header list is not something this API can pin
// (HTTP/2 goes through Go's map-backed header), so these stay UA-only.
// Measured 2026-10-15/16 against tls.browserleaks.com: 142, 143, 144, 145, 146,
// 147, 148 and 149 all read ja3n 8e19337e75… and akamai 52d84b11737d…, sixteen
// non-GREASE extensions, signature_algorithms opening on ecdsa_secp256r1_sha256
// (no ML-DSA) and no trust_anchors. Live through the library (2026-10-16, tls.peet.ws
// with with_http3=false) chrome_143 and chrome_148 answer ja4
// t13d1516h2_8daaf6152771_d8a2da3f94cd - the captures' own ja4 - and akamai
// 52d84b11737d….
// Re-measured 2026-10-17 against a second round of tls.peet.ws captures (135, 136,
// 143 through 152): peetprint, ja3, the decoded extension content and the akamai
// string are identical across 136 through 151, so the band holds. The only
// cross-version difference in that whole set is peet's ja4 for 135 and 136, which
// additionally lists extension 21 (padding) - a field peet's own extension array and
// ja3 contradict, and a shape BoringSSL only pads into when the hello is 256 to 511
// bytes, while these hellos are about 1.8 KB (136 and 148 measure the same 1768
// bytes, and only the 136 one carries the flag). See
// TestPaddingIsTheOnlyChrome136Delta before treating that as a 136 change.
var Chrome_149 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
}

var Chrome_148 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
}

var Chrome_147 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
}

var Chrome_146 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
}

var Chrome_145 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
}

var Chrome_144 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
}

var Chrome_143 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
}

var Chrome_142 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
}

// Chrome_150 is the next anchor after Chrome_136: signature_algorithms grew the
// three ML-DSA schemes (0x0904, 0x0905, 0x0906) ahead of the ECDSA/RSA list, so
// the extension content changed even though the extension set did not. Everything
// else is still Chrome_136's bytes, and Chrome 151 sends exactly these. Measured
// 2026-10-15/16 against tls.browserleaks.com (150 and 151 agree on every field)
// and tls.peet.ws, which both read sixteen extensions and the 0904,0905,0906 lead.
var Chrome_150 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
	WithHttp3:            &withHttp3,
	Client:               "chrome",
	Version:              "150",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	SignatureHashed:      "MLDSA44,MLDSA65,MLDSA87,ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPS:                 true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

// Chrome_152 is the anchor after Chrome_150: the trust_anchors extension
// (0xca34 / 51764) appears on every connection. The capture from tls.peet.ws
// lists 28 identifier/length pairs in it, because that machine had trust-anchor
// hints; a browser without them sends the same extension with an empty list, two
// length bytes - that is the shape TlsTrustAnchors produces and the one to
// impersonate. The extension count, not the content, is what ja4 and peetprint
// hash, so ja4 still matches. Measured 2026-10-15/16: seventeen non-GREASE
// extensions and ja3n bd4930bd9b… on 152, and the same set on 153, 154 and 155.
// Chrome 151 does not have it, so 152 - not 153 - is where this line starts.
// signature_algorithms opens on a random GREASE scheme from here too (0x8aaa on
// the 152 capture, 0x6a6a, 0x1a1a and 0xeaea on 153/154/155) - 150 and 151 have no
// GREASE in front, which is what dates this as a 152 change rather than a 150 one.
// That scheme is something this library cannot imitate - see "Known deviations" in
// CONTRIBUTING.md. Live through the library (2026-10-16, tls.peet.ws with
// with_http3=false) chrome_152 answers ja4 t13d1517h2_8daaf6152771_cb7bf5808d99 and
// akamai 52d84b11737d…, the pair the 152, 153 and 155 captures all report.
var Chrome_152 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
	WithHttp3:            &withHttp3,
	Client:               "chrome",
	Version:              "152",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	SignatureHashed:      "MLDSA44,MLDSA65,MLDSA87,ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsTrustAnchors:      true,
	ALPS:                 true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

// Chrome 153, 154 and 155 send Chrome_152's bytes. The one difference seen in the
// captures is a pre_shared_key extension on 154, which is that session having a
// stored ticket - a resumption hello, not a new version of the fingerprint.
var Chrome_153 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
}

var Chrome_154 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
}

var Chrome_155 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
}

var Chrome_151 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
}

var Chrome_141 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
}

var Chrome_140 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
}

var Chrome_139 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
}

var Chrome_138 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
}
var Chrome_137 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
}
var Chrome_137_ios = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/137 Version/11.1.1 Safari/605.1.15",
	WithHttp3:              &withHttp3,
	Client:                 "chrome_ios",
	Version:                "137",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,ECDSAWithSHA1,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	Http2PseudoHeaderOrder: "mspa",
	Http2Setting:           "4:2097152;3:100",
	Http2WindowUpdate:      10485760,
	Http2StreamWight:       255,
	Http2StreamExclusive:   1,
	CertCompression:        "zlib",
	TlsVersion:             "1.3",
	TlsGrease:              true,
	TlsPadding:             true,
	RandomExtensionOrder:   true,
	NoTlsSessionTicket:     true,
}
var Chrome_136 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
	WithHttp3:            &withHttp3,
	Client:               "chrome",
	Version:              "136",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPS:                 true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Chrome_135 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
}
var Chrome_134 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
}
var Chrome_133 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	WithHttp3: &withHttp3,
}

var Chrome_132 = ClientData{
	UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
	WithHttp3:            &withHttp3,
	Client:               "chrome",
	Version:              "132",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPS:                 true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

// Android 14
var Chrome_131_android = ClientData{
	UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	Client:               "chrome",
	Version:              "131_android",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

// Android 12
var Chrome_99_android = ClientData{
	UserAgent:            "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.58 Mobile Safari/537.36",
	Client:               "chrome",
	Version:              "99_android",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}
var Chrome_131 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	Client:               "chrome",
	Version:              "131",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Chrome_130 = ClientData{
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
}
var Chrome_129 = ClientData{
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
}
var Chrome_128 = ClientData{
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
}
var Chrome_127 = ClientData{
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
}
var Chrome_126 = ClientData{
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
}
var Chrome_125 = ClientData{
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
}
var Chrome_124 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	Client:               "chrome",
	Version:              "124",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519Kyber768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Chrome_123 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
}
var Chrome_122 = ClientData{
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
}
var Chrome_121 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
}
var Chrome_120 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}
var Chrome_119 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	Client:               "chrome",
	Version:              "119",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Chrome_117 = ClientData{
	UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	Client:               "chrome",
	Version:              "117",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}
var Edge_140 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
}
var Edge_139 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0",
}
var Edge_138 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
}
var Edge_137 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
}

// Edge 143 still sends the Chrome 136 band: captured 2026-10-18 against tls.peet.ws,
// every field (extension set, ciphers, groups, signature schemes, key shares, ALPN,
// SETTINGS, WINDOW_UPDATE, pseudo-header order) equals Edge_136's.
var Edge_143 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
}

// Edge 151 and 152 ride the Chrome 150 band - the ML-DSA signature schemes are there,
// trust_anchors is not. The 151 capture additionally listed pre_shared_key (41), which
// is a resumption artifact of that one connection rather than a profile field (see
// CONTRIBUTING), so it is not copied here.
var Edge_152 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 Edg/152.0.0.0",
}
var Edge_151 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
}

var Edge_136 = ClientData{
	WithHttp3:            &withHttp3,
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
	Client:               "edge",
	Version:              "131",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPS:                 true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Edge_135 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
}
var Edge_134 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
}
var Edge_133 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
}
var Edge_132 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
}
var Edge_131 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	Client:               "edge",
	Version:              "131",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPSO:                true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Edge_101 = ClientData{
	UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47",
	Client:               "edge",
	Version:              "101",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPSO:                true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}

// Firefox 153 is a new anchor: it drops TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (c009)
// from the cipher list, which is the only byte the 2026-10-18 capture moved since
// Firefox_135. One field is deliberately not inherited: this block sends record_size_limit
// as 16385, the value both the 144 and 153 captures read, where Firefox_132 and Firefox_135
// send 4001 - a decimal written where 0x4001 was meant. Firefox_153 has no users yet, so
// the slip is not carried into a new id; moving firefox_135 through firefox_144 is its own
// change, tracked in CONTRIBUTING. The other deviation of this line is inherited: key_share
// sends the GREASE entry plus two groups where Firefox sends three groups and no GREASE
// share, because TlsKeySharesLimit counts the GREASE slot against the limit.
var Firefox_153 = ClientData{
	UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:153.0) Gecko/20100101 Firefox/153.0",
	Client:                  "firefox",
	Version:                 "153",
	CipherSuites:            "TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	SignatureHashed:         "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,PSSWithSHA256,PSSWithSHA384,PSSWithSHA512,PKCS1WithSHA256,PKCS1WithSHA384,PKCS1WithSHA512,ECDSAWithSHA1,PKCS1WithSHA1",
	Compressed:              true,
	Curves:                  "X25519MLKEM768:X25519:P256:P384:P521:FAKEFFDHE2048:FAKEFFDHE3072",
	TlsDelegatedCredentials: "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,ECDSAWithSHA1",
	Http2Setting:            "1:65536;2:0;4:131072;5:16384",
	TlsRecordSizeLimit:      16385,
	Http2WindowUpdate:       12517377,
	Http2StreamWight:        43,
	Http2StreamExclusive:    0,
	Http2PseudoHeaderOrder:  "mpas",
	CertCompression:         "zlib,brotli,zstd",
	TlsExtensionOrder:       "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037",
	TlsVersion:              "1.3",
	TlsGrease:               true,
	Ech:                     true,
}
var Firefox_144 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
}
var Firefox_143 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
}
var Firefox_142 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
}
var Firefox_141 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0",
}
var Firefox_140 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
}
var Firefox_139 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0",
}
var Firefox_138 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
}
var Firefox_137 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
}
var Firefox_136 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
}
var Firefox_135 = ClientData{
	UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
	Client:                  "firefox",
	Version:                 "135",
	CipherSuites:            "TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	SignatureHashed:         "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,PSSWithSHA256,PSSWithSHA384,PSSWithSHA512,PKCS1WithSHA256,PKCS1WithSHA384,PKCS1WithSHA512,ECDSAWithSHA1,PKCS1WithSHA1",
	Compressed:              true,
	Curves:                  "X25519MLKEM768:X25519:P256:P384:P521:FAKEFFDHE2048:FAKEFFDHE3072",
	TlsDelegatedCredentials: "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,ECDSAWithSHA1",
	Http2Setting:            "1:65536;2:0;4:131072;5:16384",
	TlsRecordSizeLimit:      4001,
	Http2WindowUpdate:       12517377,
	Http2StreamWight:        43,
	Http2StreamExclusive:    0,
	Http2PseudoHeaderOrder:  "mpas",
	CertCompression:         "zlib,brotli,zstd",
	TlsExtensionOrder:       "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037",
	TlsVersion:              "1.3",
	TlsGrease:               true,
	Ech:                     true,
}
var Firefox_134 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
}
var Firefox_133 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
}
var Firefox_132 = ClientData{
	UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
	Client:                  "firefox",
	Version:                 "132",
	CipherSuites:            "TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	SignatureHashed:         "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,PSSWithSHA256,PSSWithSHA384,PSSWithSHA512,PKCS1WithSHA256,PKCS1WithSHA384,PKCS1WithSHA512,ECDSAWithSHA1,PKCS1WithSHA1",
	Compressed:              true,
	Curves:                  "X25519MLKEM768:X25519:P256:P384:P521:FAKEFFDHE2048:FAKEFFDHE3072",
	TlsDelegatedCredentials: "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,ECDSAWithSHA1",
	Http2Setting:            "1:65536;2:0;4:131072;5:16384",
	TlsRecordSizeLimit:      4001,
	Http2WindowUpdate:       12517377,
	Http2StreamWight:        43,
	Http2StreamExclusive:    0,
	Http2PseudoHeaderOrder:  "mpas",
	CertCompression:         "zlib,brotli,zstd",
	TlsExtensionOrder:       "0-23-65281-10-11-16-5-34-51-43-13-28-27-65037",
	TlsVersion:              "1.3",
	TlsGrease:               true,
	Ech:                     true,
	RandomExtensionOrder:    true,
}
var Firefox_123 = ClientData{
	UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
	Client:                  "firefox",
	Version:                 "123",
	CipherSuites:            "TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	SignatureHashed:         "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,PSSWithSHA256,PSSWithSHA384,PSSWithSHA512,PKCS1WithSHA256,PKCS1WithSHA384,PKCS1WithSHA512,ECDSAWithSHA1,PKCS1WithSHA1",
	Compressed:              true,
	Curves:                  "X25519:P256:P384:P521:FAKEFFDHE2048:FAKEFFDHE3072",
	TlsDelegatedCredentials: "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,ECDSAWithSHA1",
	Http2Setting:            "1:65536;4:131072;5:16384",
	Http2Priorities:         "3:0:0:200,5:0:0:100,7:0:0:0,9:7:0:0,11:3:0:0,13:0:0:240",
	TlsRecordSizeLimit:      16385,
	Http2WindowUpdate:       12517377,
	Http2StreamWight:        41,
	Http2StreamDep:          13,
	Http2StreamExclusive:    0,
	Http2PseudoHeaderOrder:  "mpas",
	CertCompression:         "zlib,brotli,zstd",
	TlsExtensionOrder:       "0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037",
	TlsVersion:              "1.3",
	TlsGrease:               true,
	Ech:                     true,
}
var Firefox_120 = ClientData{
	UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
	Client:                  "firefox",
	Version:                 "120",
	CipherSuites:            "TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	SignatureHashed:         "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,PSSWithSHA256,PSSWithSHA384,PSSWithSHA512,PKCS1WithSHA256,PKCS1WithSHA384,PKCS1WithSHA512,ECDSAWithSHA1,PKCS1WithSHA1",
	Compressed:              true,
	Curves:                  "X25519:P256:P384:P521:FAKEFFDHE2048:FAKEFFDHE3072",
	TlsDelegatedCredentials: "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,ECDSAWithSHA1",
	Http2Setting:            "1:65536;4:131072;5:16384",
	Http2Priorities:         "3:0:0:200,5:0:0:100,7:0:0:0,9:7:0:0,11:3:0:0,13:0:0:240",
	TlsRecordSizeLimit:      16385,
	Http2WindowUpdate:       12517377,
	Http2StreamWight:        41,
	Http2StreamDep:          13,
	Http2StreamExclusive:    0,
	Http2PseudoHeaderOrder:  "mpas",
	CertCompression:         "zlib,brotli,zstd",
	TlsExtensionOrder:       "0-23-65281-10-11-16-5-34-51-43-13-28-65037",
	TlsVersion:              "1.3",
	TlsGrease:               true,
	Ech:                     true,
}
var Firefox_117 = ClientData{
	UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:117.0) Gecko/20100101 Firefox/117.0",
	Client:                  "firefox",
	Version:                 "117",
	CipherSuites:            "TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	SignatureHashed:         "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,PSSWithSHA256,PSSWithSHA384,PSSWithSHA512,PKCS1WithSHA256,PKCS1WithSHA384,PKCS1WithSHA512,ECDSAWithSHA1,PKCS1WithSHA1",
	Compressed:              true,
	Curves:                  "X25519:P256:P384:P521:FAKEFFDHE2048:FAKEFFDHE3072",
	TlsDelegatedCredentials: "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,ECDSAWithSHA1",
	Http2Setting:            "1:65536;4:131072;5:16384",
	Http2Priorities:         "3:0:0:200,5:0:0:100,7:0:0:0,9:7:0:0,11:3:0:0,13:0:0:240",
	TlsRecordSizeLimit:      16385,
	Http2WindowUpdate:       12517377,
	Http2StreamWight:        43,
	Http2StreamExclusive:    0,
	Http2PseudoHeaderOrder:  "mpas",
	CertCompression:         "zlib,brotli,zstd",
	TlsExtensionOrder:       "0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21",
	TlsVersion:              "1.3",
	TlsGrease:               true,
	Ech:                     true,
	TlsPadding:              true,
}
var Opera_120 = ClientData{
	WithHttp3:            &withHttp3,
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 OPR/120.0.0.0",
	Client:               "opera",
	Version:              "120",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPS:                 true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

// Opera 137 is the Chrome 153 build of the Chrome 152 band: the 2026-10-18 capture
// matches chrome_152 on every field, trust_anchors and the ML-DSA schemes included,
// SETTINGS and WINDOW_UPDATE too.
var Opera_137 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 OPR/137.0.0.0",
}
var Opera_119 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/119.0.0.0",
}
var Opera_117 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0",
	Client:               "opera",
	Version:              "117",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPSO:                true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

var Safari_15_3 = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
	Client:                 "safari",
	Version:                "15.3",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,ECDSAWithSHA1,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-21",
	Http2PseudoHeaderOrder: "mspa",
	Http2Setting:           "4:4194304;3:100",
	Http2WindowUpdate:      10485760,
	Http2StreamWight:       255,
	Http2StreamDep:         0,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}
var Safari_15_5 = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
	Client:                 "safari",
	Version:                "15.5",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,ECDSAWithSHA1,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "mspa",
	Http2Setting:           "4:4194304;3:100",
	Http2WindowUpdate:      10485760,
	Http2StreamWight:       255,
	Http2StreamDep:         0,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}
var Safari_17_0 = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	Client:                 "safari",
	Version:                "17.0",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,ECDSAWithSHA1,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "mspa",
	Http2Setting:           "2:0;4:4194304;3:100",
	Http2WindowUpdate:      10485760,
	Http2StreamWight:       255,
	Http2StreamDep:         0,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}
var Safari_18_0 = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	Client:                 "safari",
	Version:                "18.0",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "msap",
	Http2Setting:           "2:0;3:100;4:2097152;8:1;9:1",
	Http2WindowUpdate:      10420225,
	Http2StreamWight:       255,
	Http2StreamDep:         0,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}

// intel chip
var Safari_18_1 = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	Client:                 "safari",
	Version:                "18.1",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,ECDSAWithSHA1,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "mspa",
	Http2Setting:           "2:0;4:4194304;3:100",
	Http2WindowUpdate:      10485760,
	Http2StreamWight:       255,
	Http2StreamDep:         0,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}

// same 18_4
var Safari_18_5 = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
	Client:                 "safari",
	Version:                "18.5",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "msap",
	Http2Setting:           "2:0;3:100;4:2097152;9:1",
	Http2WindowUpdate:      10420225,
	Http2StreamWight:       255,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}
var Safari_26_0 = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
	Client:                 "safari",
	Version:                "26.0",
	CipherSuites:           "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519MLKEM768:X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-35-16-5-13-18-51-45-43-27",
	Http2PseudoHeaderOrder: "msap",
	Http2Setting:           "2:0;3:100;4:2097152;9:1",
	Http2WindowUpdate:      10420225,
	Http2StreamWight:       255,
	Http2StreamDep:         0,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
}

// Safari 26.5 is a new band on the macOS line, captured 2026-10-18 against tls.peet.ws:
// session_ticket (35) is no longer offered at all, and supported_versions stops at
// TLS 1.2 instead of claiming 1.1 and 1.0. The cipher list is untouched - all twenty
// suites, 3DES included, which ja4_r confirms went out on the wire. Everything else,
// signature schemes, groups, key shares, SETTINGS and the msap pseudo-header order, is
// Safari_26_0's, and the extension order is the same list with 35 removed.
//
// That removal and NoTlsSessionTicket are two halves of one fact: the flag deletes 35 from
// the extension map, so a profile that sets it and still names 35 in the order fails the
// build with "don't support this ext: 35" instead of silently sending the extension.
var Safari_26_5 = ClientData{
	UserAgent:              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15",
	Client:                 "safari",
	Version:                "26.5",
	CipherSuites:           "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519MLKEM768:X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27",
	Http2PseudoHeaderOrder: "msap",
	Http2Setting:           "2:0;3:100;4:2097152;9:1",
	Http2WindowUpdate:      10420225,
	Http2StreamWight:       255,
	Http2StreamDep:         0,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	// "1.3" is what puts the GREASE value in front of supported_versions, the way this
	// Safari sends it; "any" would list TLS 1.1 and 1.0 as well.
	TlsVersion:         "1.3",
	TlsGrease:          true,
	NoTlsSessionTicket: true,
}

var Safari_ios_17_0 = ClientData{
	UserAgent:              "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
	Client:                 "safari_ios",
	Version:                "17.0",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,ECDSAWithSHA1,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "mspa",
	Http2Setting:           "2:0;4:2097152;3:100",
	Http2WindowUpdate:      10485760,
	Http2StreamWight:       255,
	Http2StreamExclusive:   1,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}
var Safari_ios_18_0 = ClientData{
	UserAgent:              "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	Client:                 "safari_ios",
	Version:                "18.0",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "msap",
	Http2Setting:           "2:0;3:100;4:2097152;8:1;9:1",
	Http2WindowUpdate:      10420225,
	Http2StreamWight:       255,
	Http2StreamDep:         0,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}
var Safari_ios_18_5 = ClientData{
	UserAgent:              "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
	Client:                 "safari_ios",
	Version:                "18.5",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "msap",
	Http2Setting:           "2:0;3:100;4:2097152;9:1",
	Http2WindowUpdate:      10420225,
	Http2StreamWight:       255,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
	NoTlsSessionTicket:     true,
}
var Safari_ios_26_0 = ClientData{
	UserAgent:              "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
	Client:                 "safari_ios",
	Version:                "26.0",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Curves:                 "X25519:P256:P384:P521",
	TlsExtensionOrder:      "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21",
	Http2PseudoHeaderOrder: "msap",
	Http2Setting:           "2:0;3:100;4:2097152;9:1",
	Http2WindowUpdate:      10420225,
	Http2StreamWight:       255,
	Http2StreamExclusive:   0,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	TlsGrease:              true,
	TlsPadding:             true,
}

// base on firefox 128
var Tor_14_5 = ClientData{
	UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
	Client:                  "tor",
	Version:                 "14.5",
	CipherSuites:            "TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:                  "X25519:P256:P384:P521:FAKEFFDHE2048:FAKEFFDHE3072",
	TlsDelegatedCredentials: "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,ECDSAWithSHA1",
	SignatureHashed:         "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,PSSWithSHA256,PSSWithSHA384,PSSWithSHA512,PKCS1WithSHA256,PKCS1WithSHA384,PKCS1WithSHA512,ECDSAWithSHA1,PKCS1WithSHA1",
	TlsExtensionOrder:       "0-23-65281-10-11-16-5-34-51-43-13-28-65037",
	Http2Setting:            "1:65536;2:0;4:131072;5:16384",
	Http2WindowUpdate:       12517377,
	Http2StreamWight:        42,
	Http2StreamExclusive:    0,
	CertCompression:         "brotli",
	Http2PseudoHeaderOrder:  "mpas",
	TlsRecordSizeLimit:      16385,
	TlsVersion:              "1.3",
	TlsGrease:               true,
	Ech:                     true,
}

// base on chrome 138
var Brave_1_8 = ClientData{
	WithHttp3:            &withHttp3,
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
	Client:               "brave",
	Version:              "1.8",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPS:                 true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

// Brave 1.97 is the Chrome 155 build of the Chrome 150 band: captured 2026-10-18, the
// hello is identical to chrome_150's and Brave's own UA stays the plain Chrome one
// (Brave hides its brand by default, which is also why Brave_1_8's UA has no "Brave").
var Brave_1_97 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
}

// QQ Browser 19.4 on a Chrome 123 core. Its hello is a Chrome line of its own: the
// extension order carries padding (21), and key_share holds only the GREASE entry plus
// X25519 - one real group, so TlsKeySharesLimit is 2 because the GREASE slot is one of
// the three the default limit counts.
var QQ_19_4 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 QQBrowser/19.4.0.207",
	Client:               "QQ",
	Version:              "19.4",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519:P256:P384",
	TlsExtensionOrder:    "17513-51-65281-13-27-23-16-10-0-35-18-45-5-43-11-65037-21",
	Compressed:           true,
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	TlsKeySharesLimit:    2,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsPadding:           true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

// QQ Browser 22.1 runs a Chrome 138 core and sends exactly that Chrome's bytes: the
// 2026-10-18 capture matches the Chrome_136 anchor on every field, so it rides it.
var QQ_22_1 = ClientData{
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 QQBrowser/22.1.0.219",
}

// base on chrome 132
var QH360_16_0 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
	Client:               "360",
	Version:              "16.0",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Compressed:           true,
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var QH360_5_5_ios = ClientData{
	UserAgent:              "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/615.3.12 (KHTML, like Gecko) Mobile/20H115 Version/16.7 Safari/604.1",
	Client:                 "360_ios",
	Version:                "5.5",
	CipherSuites:           "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	SignatureHashed:        "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,ECDSAWithSHA1,PSSWithSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512,PKCS1WithSHA1",
	Http2PseudoHeaderOrder: "mspa",
	Compressed:             true,
	Curves:                 "X25519:P256:P384:P521",
	Http2Setting:           "4:2097152;3:100",
	Http2WindowUpdate:      10485760,
	Http2StreamWight:       255,
	Http2StreamExclusive:   1,
	CertCompression:        "zlib",
	TlsVersion:             "any",
	NoTlsSessionTicket:     true,
	TlsGrease:              true,
	TlsPadding:             true,
	RandomExtensionOrder:   true,
}

// UC PC 1.1.0.9 on a Chrome 130 core.
//
// This block used to be discarded over its last SETTINGS pair, "43706:3053153145",
// which read like a settings id over the 16-bit maximum. It is not one: HTTP/2 SETTINGS
// ids are 16 bits, values are 32 bits, and the trailing pair is a GREASE entry -
// browserleaks prints it as the word GREASE, and tls.peet.ws printed the same browser
// two days apart as 35466:3845491299 (0x8aaa) where this profile sends 0xaaaa. Both are
// samples of the same shape, so the pair stays.
var UC_110_9 = ClientData{
	UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 UCPC/1.1.0.9",
	Client:               "uc",
	Version:              "1.1.0.9",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144;43706:3053153145",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	TlsKeySharesLimit:    2,
	ALPSO:                true,
	ALPSS:                true,
	// CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var UC_ios_17_9 = ClientData{
	UserAgent:            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X; zh-CN) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/20H115 UCBrowser/17.7.8.2650 Mobile  AliApp(TUnionSDK/0.1.20.4)",
	Client:               "uc",
	Version:              "17.9",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	ALPSS:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}

// base on chrome 125
var Samsung_27_1 = ClientData{
	UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.1 Chrome/125.0.0.0 Mobile Safari/537.36",
	Client:               "samsung",
	Version:              "27.1",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

var Xiaomi_15_9 = ClientData{
	UserAgent:            "Mozilla/5.0 (Linux; U; Android 11; zh-cn; M2006C3LC Build/RP1A.200720.011) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 XiaoMi/MiuiBrowser/15.9.16 swan-mibrowser",
	Client:               "xiaomi",
	Version:              "15.9",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     255,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsPadding:           true,
}
