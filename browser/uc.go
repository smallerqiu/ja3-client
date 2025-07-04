package browser

import (
	"github.com/smallerqiu/ja3-client/http2"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
	tls "github.com/smallerqiu/utls"
)

var UC_17_3 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "UC",
		RandomExtensionOrder: false,
		Version:              "17.3",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS10,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,                            //2570
					tls.TLS_AES_128_GCM_SHA256,                        //4856
					tls.TLS_AES_256_GCM_SHA384,                        //4866
					tls.TLS_CHACHA20_POLY1305_SHA256,                  // 5867
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       //49195
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         //49199
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       //49196
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         //49200
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, //52393
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   //52392
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            //49171
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            // 49172
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,               //156
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,               //157
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,                  //47
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,                  //53
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.SCTExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1", "h2"}},
					&tls.StatusRequestExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519,
						tls.CurveP256, //23
						tls.CurveP384, //24
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256, //1027
							tls.PSSWithSHA256,          //2052
							tls.PKCS1WithSHA256,        //1025
							tls.ECDSAWithP384AndSHA384, //1283
							tls.PSSWithSHA384,          //2053
							tls.PKCS1WithSHA384,        //1281
							tls.PSSWithSHA512,          //2054
							tls.PKCS1WithSHA512,        //1537
						}},
					&tls.ApplicationSettingsExtension{
						CodePoint:          tls.ExtensionALPSOld,
						SupportedProtocols: []string{"h2"},
					},

					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}, // 21
				},
			}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	ConnectionFlow: 15663105,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: true,
		Weight:    0,
	},
}
