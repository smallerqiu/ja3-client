package browser

import (
	"github.com/smallerqiu/ja3-client/http2"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
	tls "github.com/smallerqiu/utls"
)

var Custom = ja3.ClientProfile{
	// 对标chrome 108.0
	ClientHelloId: tls.ClientHelloID{
		Client:               "Custom",
		RandomExtensionOrder: false,
		Version:              "14.5",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS12,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_256_GCM_SHA384,                        //4866
					tls.TLS_AES_128_GCM_SHA256,                        //4865
					tls.TLS_CHACHA20_POLY1305_SHA256,                  //5867
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       //49196
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       //49195
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, //52393
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         //49200
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   //52392
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         //49199
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            //49172
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            //49171
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,               //157
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,               //156
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,                  //53
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,                  //47
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.StatusRequestExtension{},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,        //29
						tls.CurveP256,     //23
						tls.CurveP384,     //24
						tls.CurveP521,     //25
						tls.X448,          //30
						tls.FAKEFFDHE2048, //256
						tls.FAKEFFDHE3072, //257
						tls.FAKEFFDHE4096, //258
						tls.FAKEFFDHE6144, //259
						tls.FAKEFFDHE8192, //260
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestV2Extension{}, //17
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256, //1027
						tls.ECDSAWithP384AndSHA384, //1283
						tls.ECDSAWithP521AndSHA512, //1539
						tls.Ed25519,                //2055
						tls.FAKEEd25519,            //2056
						tls.PSSWithSHA256,          //2052
						tls.PSSWithSHA384,          //2053
						tls.PSSWithSHA512,          //2054
						tls.PSSPASSSHA256,          //2057,
						tls.PSSPASSSHA384,          //2058,
						tls.PSSPASSSHA512,          //2059,
						tls.PKCS1WithSHA256,        //1025,
						tls.PKCS1WithSHA384,        //1281,
						tls.PKCS1WithSHA512,        //1537,
						tls.DSAWithSHA256,          //1026,
						tls.SHA224_ECDSA,           //771,
						tls.SHA224_RSA,             //769,
						tls.DSAWithSHA224,          //770,
						tls.ECDSAWithSHA1,          //515,
						tls.PKCS1WithSHA1,          //513,
						tls.DASWithSHA1,            //514,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SignatureAlgorithmsCertExtension{ //50
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256, //1027
							tls.ECDSAWithP384AndSHA384, //1283
							tls.ECDSAWithP521AndSHA512, //1539
							tls.Ed25519,                //2055
							tls.FAKEEd25519,            //2056
							tls.PSSWithSHA256,          //2052
							tls.PSSWithSHA384,          //2053
							tls.PSSWithSHA512,          //2054
							tls.PSSPASSSHA256,          //2057,
							tls.PSSPASSSHA384,          //2058,
							tls.PSSPASSSHA512,          //2059,
							tls.PKCS1WithSHA256,        //1025,
							tls.PKCS1WithSHA384,        //1281,
							tls.PKCS1WithSHA512,        //1537,
							tls.DSAWithSHA256,          //1026,
							tls.SHA224_ECDSA,           //771,
							tls.SHA224_RSA,             //769,
							tls.DSAWithSHA224,          //770,
							tls.ECDSAWithSHA1,          //515,
							tls.PKCS1WithSHA1,          //513,
							tls.DASWithSHA1,            //514,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
				},
			}, nil
		},
	},
	Settings: map[http2.SettingID]uint32{
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 4194304,
		http2.SettingMaxHeaderListSize: 10485760,
	},
	SettingsOrder: []http2.SettingID{
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
	ConnectionFlow: 1073741824,
	HeaderPriority: &http2.PriorityParam{},
}
