package ja3

import (
	"github.com/smallerqiu/ja3-client/http2"
	tls "github.com/smallerqiu/utls"
	"github.com/smallerqiu/utls/dicttls"
)

var CipherSuites = map[string]uint16{
	"GREASE_PLACEHOLDER,":                           tls.GREASE_PLACEHOLDER,
	"TLS_RSA_WITH_RC4_128_SHA":                      tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_256_CBC_SHA256":               tls.TLS_RSA_WITH_AES_256_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_AES_128_GCM_SHA256":                        tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":                        tls.TLS_AES_256_GCM_SHA384,
	"TLS_CHACHA20_POLY1305_SHA256":                  tls.TLS_CHACHA20_POLY1305_SHA256,
	"TLS_FALLBACK_SCSV":                             tls.TLS_FALLBACK_SCSV,
	"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA":         tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":          tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
}

var H2SettingsMap = map[string]http2.SettingID{
	"HEADER_TABLE_SIZE":      http2.SettingHeaderTableSize,
	"ENABLE_PUSH":            http2.SettingEnablePush,
	"MAX_CONCURRENT_STREAMS": http2.SettingMaxConcurrentStreams,
	"INITIAL_WINDOW_SIZE":    http2.SettingInitialWindowSize,
	"MAX_FRAME_SIZE":         http2.SettingMaxFrameSize,
	"MAX_HEADER_LIST_SIZE":   http2.SettingMaxHeaderListSize,
	"UNKNOWN_SETTING_7":      0x7,
	"UNKNOWN_SETTING_8":      0x8,
	"UNKNOWN_SETTING_9":      0x9,
}
var H2SettingsOrder = map[string]http2.SettingID{
	"1": http2.SettingHeaderTableSize,
	"2": http2.SettingEnablePush,
	"3": http2.SettingMaxConcurrentStreams,
	"4": http2.SettingInitialWindowSize,
	"5": http2.SettingMaxFrameSize,
	"6": http2.SettingMaxHeaderListSize,
	"7": 0x7,
	"8": 0x8,
	"9": 0x9,
}

var tlsVersions = map[string]uint16{
	"GREASE": tls.GREASE_PLACEHOLDER,
	"1.3":    tls.VersionTLS13,
	"1.2":    tls.VersionTLS12,
	"1.1":    tls.VersionTLS11,
	"1.0":    tls.VersionTLS10,
}

var signatureAlgorithms = map[string]tls.SignatureScheme{
	"PKCS1WithSHA256":        tls.PKCS1WithSHA256,
	"DSAWithSHA256":          tls.DSAWithSHA256,
	"PKCS1WithSHA384":        tls.PKCS1WithSHA384,
	"PKCS1WithSHA512":        tls.PKCS1WithSHA512,
	"PSSWithSHA256":          tls.PSSWithSHA256,
	"PSSWithSHA384":          tls.PSSWithSHA384,
	"PSSWithSHA512":          tls.PSSWithSHA512,
	"PSSPASSSHA256":          tls.PSSPASSSHA256,
	"PSSPASSSHA384":          tls.PSSPASSSHA384,
	"PSSPASSSHA512":          tls.PSSPASSSHA512,
	"ECDSAWithP256AndSHA256": tls.ECDSAWithP256AndSHA256,
	"ECDSAWithP384AndSHA384": tls.ECDSAWithP384AndSHA384,
	"ECDSAWithP521AndSHA512": tls.ECDSAWithP521AndSHA512,
	"PKCS1WithSHA1":          tls.PKCS1WithSHA1,
	"DASWithSHA1":            tls.DASWithSHA1,
	"ECDSAWithSHA1":          tls.ECDSAWithSHA1,
	"Ed25519":                tls.Ed25519,
	"FAKEEd25519":            tls.FAKEEd25519,
	"SHA224_RSA":             tls.SHA224_RSA,
	"SHA224_ECDSA":           tls.SHA224_ECDSA,
	"DSAWithSHA224":          tls.DSAWithSHA224,
}

var delegatedCredentialsAlgorithms = map[string]tls.SignatureScheme{
	"PKCS1WithSHA256":        tls.PKCS1WithSHA256,
	"PKCS1WithSHA384":        tls.PKCS1WithSHA384,
	"PKCS1WithSHA512":        tls.PKCS1WithSHA512,
	"PSSWithSHA256":          tls.PSSWithSHA256,
	"PSSWithSHA384":          tls.PSSWithSHA384,
	"PSSWithSHA512":          tls.PSSWithSHA512,
	"ECDSAWithP256AndSHA256": tls.ECDSAWithP256AndSHA256,
	"ECDSAWithP384AndSHA384": tls.ECDSAWithP384AndSHA384,
	"ECDSAWithP521AndSHA512": tls.ECDSAWithP521AndSHA512,
	"PKCS1WithSHA1":          tls.PKCS1WithSHA1,
	"ECDSAWithSHA1":          tls.ECDSAWithSHA1,
	"Ed25519":                tls.Ed25519,
}

var kdfIds = map[string]uint16{
	"HKDF_SHA256": dicttls.HKDF_SHA256,
	"HKDF_SHA384": dicttls.HKDF_SHA384,
	"HKDF_SHA512": dicttls.HKDF_SHA512,
}

var aeadIds = map[string]uint16{
	"AEAD_AES_128_GCM":       dicttls.AEAD_AES_128_GCM,
	"AEAD_AES_256_GCM":       dicttls.AEAD_AES_256_GCM,
	"AEAD_CHACHA20_POLY1305": dicttls.AEAD_CHACHA20_POLY1305,
}

var curves = map[string]tls.CurveID{
	"GREASE":          tls.CurveID(tls.GREASE_PLACEHOLDER),
	"P256":            tls.CurveP256,
	"P384":            tls.CurveP384,
	"P521":            tls.CurveP521,
	"X25519":          tls.X25519,
	"X448":            tls.X448,
	"P256Kyber768":    tls.P256Kyber768Draft00,
	"X25519Kyber512D": tls.X25519Kyber512Draft00,
	"X25519Kyber768":  tls.X25519Kyber768Draft00,
	"X25519MLKEM768":  tls.X25519MLKEM768,
}
var pseudoHeader = map[string]string{
	"m": ":method",
	"a": ":authority",
	"s": ":scheme",
	"p": ":path",
}

var certCompression = map[string]tls.CertCompressionAlgo{
	"zlib":   tls.CertCompressionZlib,
	"brotli": tls.CertCompressionBrotli,
	"zstd":   tls.CertCompressionZstd,
}
