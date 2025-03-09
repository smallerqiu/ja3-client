package browser

import (
	"github.com/smallerqiu/ja3-client/http2"
	tls "github.com/smallerqiu/utls"
	"github.com/smallerqiu/utls/dicttls"
)

// SamsungBrowser
var Sansung_27_1 = ClientProfile{
	// 对标chrome 89.0
	clientHelloId: tls.ClientHelloID{
		Client:               "SamsungBrowser",
		RandomExtensionOrder: false,
		Version:              "27.1",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS12,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,                            //2570
					tls.TLS_AES_128_GCM_SHA256,                        //4865
					tls.TLS_AES_256_GCM_SHA384,                        //4866
					tls.TLS_CHACHA20_POLY1305_SHA256,                  // 5867
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       //49195
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         //49199
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       //49196
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         //49200
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, //52393
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   //52392
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            //49171
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            //49172
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,               //156
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,               //157
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,                  //47
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,                  //53
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{}, //2570 , GREASE
					&tls.SupportedPointsExtension{SupportedPoints: []byte{ //11 ,ec_point_formats
						tls.PointFormatUncompressed,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{ //27 ,compress_certificate
						tls.CertCompressionBrotli,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //16 ,application_layer_protocol_negotiation
					&tls.SupportedVersionsExtension{Versions: []uint16{ //43 ,supported_versions
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.ApplicationSettingsExtension{ //17513 ,application_settings_old
						SupportedProtocols: []string{"h2"},
					},
					&tls.SCTExtension{}, //18 ,signed_certificate_timestamp
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{ //51 ,key_share
						{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.ExtendedMasterSecretExtension{}, //23 ,extended_master_secret
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{ //13 ,signature_algorithms
						tls.ECDSAWithP256AndSHA256, //1027
						tls.PSSWithSHA256,          //2052
						tls.PKCS1WithSHA256,        //1025
						tls.ECDSAWithP384AndSHA384, //1283
						tls.PSSWithSHA384,          //2053
						tls.PKCS1WithSHA384,        //1281
						tls.PSSWithSHA512,          //2054
						tls.PKCS1WithSHA512,        //1537
					}},
					&tls.StatusRequestExtension{}, //5 ,status_request
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{182, 32, 240}, // +16: 144, 239
					},
					&tls.SessionTicketExtension{}, // 35  ,session_ticket
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{ //10 ,supported_groups
						tls.GREASE_PLACEHOLDER,
						tls.X25519,
						tls.CurveP256, //23
						tls.CurveP384, //24
					}},
					&tls.RenegotiationInfoExtension{ //65281 , renegotiation_info
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{ //45  ,psk_key_exchange_modes
						tls.PskModeDHE,
					}},
					&tls.SNIExtension{},        //0 , server_name
					&tls.UtlsGREASEExtension{}, //2570 , GREASE
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
	headerPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: true,
		Weight:    0,
	},
}
