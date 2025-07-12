package ja3

var Chrome_136 = ClientData{
	Client:               "chrome",
	Version:              "136",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPS:                 true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Chrome_133 = ClientData{
	//same 132
}

var Chrome_132 = ClientData{
	Client:               "chrome",
	Version:              "132",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
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
	Client:               "chrome",
	Version:              "131_android",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
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
	Client:               "chrome",
	Version:              "99_android",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}
var Chrome_131 = ClientData{
	Client:               "chrome",
	Version:              "131",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Chrome_124 = ClientData{
	Client:               "chrome",
	Version:              "124",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519Kyber768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Chrome_120 = ClientData{
	// same 119
}
var Chrome_119 = ClientData{
	Client:               "chrome",
	Version:              "119",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Chrome_117 = ClientData{
	Client:               "chrome",
	Version:              "117",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}
var Edge_136 = ClientData{
	Client:               "edge",
	Version:              "131",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPS:                 true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Edge_131 = ClientData{
	Client:               "edge",
	Version:              "131",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPSO:                true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Edge_101 = ClientData{
	Client:               "edge",
	Version:              "101",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPSO:                true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}

var Firefox_135 = ClientData{
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
var Firefox_133 = ClientData{
	//same 132
}
var Firefox_132 = ClientData{
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
	Client:               "opera",
	Version:              "120",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPS:                 true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}
var Opera_119 = ClientData{
	// same 117
}
var Opera_117 = ClientData{
	Client:               "opera",
	Version:              "117",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	ALPSO:                true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

var Safari_15_3 = ClientData{}
var Safari_15_5 = ClientData{}
var Safari_17_0 = ClientData{}
var Safari_18_0 = ClientData{}
var Safari_18_1 = ClientData{}
var Safari_18_4 = ClientData{}
var Safari_26_0 = ClientData{}
var Safari_ios_17_2 = ClientData{}
var Safari_ios_18_0 = ClientData{}
var Safari_ios_18_4 = ClientData{}
var Safari_ios_26_0 = ClientData{}

// base on firefox 128
var Tor_14_5 = ClientData{
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
	Client:               "brave",
	Version:              "1.8",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPS:                 true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

var QQ_19_4 = ClientData{
	// same as qq_13_5
}

// base on chrome 132
var QH360_16_0 = ClientData{
	Client:               "360",
	Version:              "14.5",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519MLKEM768:X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}

var UC_17_9 = ClientData{
	Client:               "uc",
	Version:              "17.9",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
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
	Client:               "samsung",
	Version:              "27.1",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;2:0;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	ALPSO:                true,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	Ech:                  true,
	RandomExtensionOrder: true,
}

var Xiaomi_15_9 = ClientData{
	Client:               "xiaomi",
	Version:              "15.9",
	CipherSuites:         "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
	Compressed:           true,
	Curves:               "X25519:P256:P384",
	Http2Setting:         "1:65536;3:1000;4:6291456;6:262144",
	Http2WindowUpdate:    15663105,
	Http2StreamWight:     256,
	Http2StreamExclusive: 1,
	CertCompression:      "brotli",
	TlsVersion:           "1.3",
	TlsGrease:            true,
	TlsPadding:           true,
	RandomExtensionOrder: true,
}
