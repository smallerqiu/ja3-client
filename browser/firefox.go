package browser

import (
	"github.com/smallerqiu/ja3-client/http2"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
	tls "github.com/smallerqiu/utls"
	"github.com/smallerqiu/utls/dicttls"
)

var Firefox_136 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "136",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,                        //4865
					tls.TLS_CHACHA20_POLY1305_SHA256,                  //4867
					tls.TLS_AES_256_GCM_SHA384,                        //4866
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       //49195
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         //49199
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, //52393
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   //52392
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       //49196
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         //49200
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,          //49162
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,          //49161
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
					&tls.SNIExtension{},                  //0
					&tls.ExtendedMasterSecretExtension{}, //23
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, //65281
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{ //10
							tls.X25519MLKEM768,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
							tls.FAKEFFDHE2048,
							tls.FAKEFFDHE3072,
						},
					},
					&tls.SupportedPointsExtension{
						SupportedPoints: []byte{ //11
							tls.PointFormatUncompressed,
						},
					},
					&tls.SessionTicketExtension{}, //35

					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //16
					&tls.StatusRequestExtension{},                                 //5
					&tls.DelegatedCredentialsExtension{
						//34
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.SCTExtension{},

					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{ //51
							{Group: tls.X25519MLKEM768},
							{Group: tls.X25519},
							{Group: tls.CurveP256},
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{ //43
							tls.VersionTLS13,
							tls.VersionTLS12,
						},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.ECDSAWithSHA1,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
							tls.CertCompressionBrotli,
							tls.CertCompressionZstd,
						},
					},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{192, 128, 223}, // +16: 144, 239
					},
				},
			}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    43,
	},
}

var Firefox_135 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "135",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,                        //4865
					tls.TLS_CHACHA20_POLY1305_SHA256,                  //4867
					tls.TLS_AES_256_GCM_SHA384,                        //4866
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       //49195
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         //49199
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, //52393
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   //52392
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       //49196
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         //49200
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,          //49162
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,          //49161
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
					&tls.SNIExtension{},                  //0
					&tls.ExtendedMasterSecretExtension{}, //23
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, //65281
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{ //10
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{ //11
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{}, //35

					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //16
					&tls.StatusRequestExtension{},                                 //5
					&tls.DelegatedCredentialsExtension{ //34
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.SCTExtension{},

					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{ //51
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{ //43
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
						tls.CertCompressionBrotli,
						tls.CertCompressionZstd,
					},
					},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{192, 128, 223}, // +16: 144, 239
					},
				}}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    43,
	},
}

var Firefox_133 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "133",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
						tls.CertCompressionBrotli,
						tls.CertCompressionZstd,
					}},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_256_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{192, 128, 223}, // +16: 144, 239
					},
				},
			}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
}

var Firefox_132 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "132",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
						tls.CertCompressionBrotli,
						tls.CertCompressionZstd,
					}},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_256_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{192, 128, 223}, // +16: 144, 239
					},
				},
			}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
}

var Firefox_129 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "129",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},

					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{192, 128, 223}, // +16: 144, 239
					},
				},
			}, nil
		},
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    42,
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
}

// new
var Firefox_124 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "124",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},

					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
						},
						CandidatePayloadLens: []uint16{192, 128, 223}, // +16: 144, 239
					},
				}}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12451840,
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    201,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    101,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    1,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    1,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    1,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    241,
		}},
	},
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    42,
	},
}

var Firefox_123 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "123",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},

					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					tls.BoringGREASEECH(),
				}}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
}

var Firefox_120 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "120",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},

					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					tls.BoringGREASEECH(),
				}}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_117 = ja3.ClientProfile{
	ClientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "117",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},

					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_110 = ja3.ClientProfile{
	ClientHelloId: tls.HelloFirefox_110,
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_108 = ja3.ClientProfile{
	ClientHelloId: tls.HelloFirefox_108,
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_106 = ja3.ClientProfile{
	ClientHelloId: tls.HelloFirefox_106,
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_105 = ja3.ClientProfile{
	ClientHelloId: tls.HelloFirefox_105,
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_104 = ja3.ClientProfile{
	ClientHelloId: tls.HelloFirefox_104,
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}

var Firefox_102 = ja3.ClientProfile{
	ClientHelloId: tls.HelloFirefox_102,
	Settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	SettingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	ConnectionFlow: 12517377,
	HeaderPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	Priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}
