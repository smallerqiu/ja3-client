package browser

import (
	"github.com/smallerqiu/ja3-client/http2"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
	tls "github.com/smallerqiu/utls"
	"github.com/smallerqiu/utls/dicttls"
)

var QQ_13_5 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "QQ",
		RandomExtensionOrder: false,
		Version:              "13.5",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS12,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.GREASE_PLACEHOLDER,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						}},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SNIExtension{},
					&tls.SessionTicketExtension{},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{2, 32, 144},
					},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ApplicationSettingsExtension{
						CodePoint:          tls.ExtensionALPSOld,
						SupportedProtocols: []string{"h2"},
					},

					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},

					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},

					&tls.StatusRequestExtension{},
					&tls.ExtendedMasterSecretExtension{},

					&tls.SCTExtension{},

					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
						{Group: tls.X25519},
					}},

					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					&tls.UtlsGREASEExtension{},
				},
			}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
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
		Exclusive: false,
		Weight:    0,
	},
}
