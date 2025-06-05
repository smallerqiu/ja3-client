package browser

import (
	"github.com/smallerqiu/ja3-client/http2"
	tls "github.com/smallerqiu/utls"
	"github.com/smallerqiu/utls/dicttls"
)

var Edge_136 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Edge",
		RandomExtensionOrder: true,
		Version:              "136",
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
					&tls.ApplicationSettingsExtension{
						CodePoint:          tls.ExtensionALPS,
						SupportedProtocols: []string{"h2"},
					},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
							{Group: tls.X25519MLKEM768},
							{Group: tls.X25519},
						}},
					&tls.SessionTicketExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{128, 160, 192}, // +16: 144, 176, 208
					},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
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
					&tls.SNIExtension{},
					&tls.UtlsCompressCertExtension{ //27
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						}},
					&tls.StatusRequestExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{ //10
						Curves: []tls.CurveID{
							tls.GREASE_PLACEHOLDER,
							tls.X25519MLKEM768,
							tls.X25519,
							tls.CurveP256, //23
							tls.CurveP384, //24
						}},
					&tls.UtlsGREASEExtension{},
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

var Edge_134 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Edge",
		RandomExtensionOrder: true,
		Version:              "134",
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
					&tls.ExtendedMasterSecretExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SCTExtension{},
					&tls.SessionTicketExtension{},
					&tls.ApplicationSettingsExtension{
						CodePoint:          tls.ExtensionALPSOld,
						SupportedProtocols: []string{"h2"},
					},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.GREASEEncryptedClientHelloExtension{ //65037
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{128, 160, 192}, // +16: 144, 176, 208
					},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256, //1027
						tls.PSSWithSHA256,          //2052
						tls.PKCS1WithSHA256,        //1025
						tls.ECDSAWithP384AndSHA384, //1283
						tls.PSSWithSHA384,          //2053
						tls.PKCS1WithSHA384,        //1281
						tls.PSSWithSHA512,          //2054
						tls.PKCS1WithSHA512,        //1537
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256, //23
						tls.CurveP384, //24
					}},

					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.StatusRequestExtension{},
					&tls.SNIExtension{},
					&tls.UtlsGREASEExtension{},
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

var Edge_133 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Edge",
		RandomExtensionOrder: true,
		Version:              "133",
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
					&tls.ExtendedMasterSecretExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SCTExtension{},
					&tls.SessionTicketExtension{},
					&tls.ApplicationSettingsExtension{
						CodePoint:          tls.ExtensionALPSOld,
						SupportedProtocols: []string{"h2"},
					},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.GREASEEncryptedClientHelloExtension{ //65037
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{128, 160, 192}, // +16: 144, 176, 208
					},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256, //1027
						tls.PSSWithSHA256,          //2052
						tls.PKCS1WithSHA256,        //1025
						tls.ECDSAWithP384AndSHA384, //1283
						tls.PSSWithSHA384,          //2053
						tls.PKCS1WithSHA384,        //1281
						tls.PSSWithSHA512,          //2054
						tls.PKCS1WithSHA512,        //1537
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256, //23
						tls.CurveP384, //24
					}},

					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.StatusRequestExtension{},
					&tls.SNIExtension{},
					&tls.UtlsGREASEExtension{},
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

var Edge_131 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Edge",
		RandomExtensionOrder: true,
		Version:              "131",
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
					&tls.ExtendedMasterSecretExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SCTExtension{},
					&tls.SessionTicketExtension{},
					&tls.ApplicationSettingsExtension{
						CodePoint:          tls.ExtensionALPSOld,
						SupportedProtocols: []string{"h2"},
					},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.GREASEEncryptedClientHelloExtension{ //65037
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{128, 160, 192}, // +16: 144, 176, 208
					},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256, //1027
						tls.PSSWithSHA256,          //2052
						tls.PKCS1WithSHA256,        //1025
						tls.ECDSAWithP384AndSHA384, //1283
						tls.PSSWithSHA384,          //2053
						tls.PKCS1WithSHA384,        //1281
						tls.PSSWithSHA512,          //2054
						tls.PKCS1WithSHA512,        //1537
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256, //23
						tls.CurveP384, //24
					}},

					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.StatusRequestExtension{},
					&tls.SNIExtension{},
					&tls.UtlsGREASEExtension{},
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
