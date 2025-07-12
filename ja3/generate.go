package ja3

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"github.com/smallerqiu/ja3-client/http2"
	"github.com/smallerqiu/ja3-client/util"
	tls "github.com/smallerqiu/utls"
	"github.com/smallerqiu/utls/dicttls"
)

func getExtBaseMap() map[uint16]tls.TLSExtension {
	return map[uint16]tls.TLSExtension{
		// 0
		tls.ExtensionServerName: &tls.SNIExtension{},
		// 5
		tls.ExtensionStatusRequest: &tls.StatusRequestExtension{},
		// 16
		tls.ExtensionALPN: &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		// 18
		tls.ExtensionSCT: &tls.SCTExtension{},
		// 23
		tls.ExtensionExtendedMasterSecret: &tls.ExtendedMasterSecretExtension{},
		// 35
		tls.ExtensionSessionTicket: &tls.SessionTicketExtension{},
		// 45
		tls.ExtensionPSKModes: &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		// 65281
		tls.ExtensionRenegotiationInfo: &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}
}
func BuildClientHelloSpec(config ClientData) (profile ClientProfile, err error) {
	// 771
	// 4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53
	// 23-27-5-45-13-11-18-17613-16-65281-43-51-65037-35-0-10
	// 4588-29-23-24
	// 0

	var clientHelloSpec tls.ClientHelloSpec
	// ciphers part 1
	var ciphers = []uint16{}
	// if grease is true, so the extention is to use grease twice.
	if config.TlsGrease {
		ciphers = append(ciphers, uint16(tls.GREASE_PLACEHOLDER))
	}
	for _, cipher := range util.AllToUpper(strings.Split(config.CipherSuites, ",")) {
		cipherId, ok := CipherSuites[cipher]
		if ok {
			ciphers = append(ciphers, cipherId)
		} else {
			return profile, fmt.Errorf("cipher not found: %s", cipher)
		}
	}
	clientHelloSpec.CipherSuites = ciphers
	// compression
	if config.Compressed {
		clientHelloSpec.CompressionMethods = []byte{tls.CompressionNone}
	}
	// setting
	var settings = map[http2.SettingID]uint32{}
	var settingsOrder []http2.SettingID
	if config.Http2Setting != "" {
		for _, s := range strings.Split(config.Http2Setting, ";") {
			s := strings.Split(s, ":")
			if len(s) != 2 {
				return profile, fmt.Errorf("invalid http2 setting: %s", s)
			}
			id, ok := H2SettingsOrder[s[0]]
			if !ok {
				return profile, fmt.Errorf("invalid http2 setting: %s", s[0])
			}
			idStr := s[1]
			idUint, err := strconv.ParseUint(idStr, 10, 32)
			if err != nil {
				return profile, fmt.Errorf("failed to parse extension ID: %v", err)
			}
			settings[id] = uint32(idUint)
			settingsOrder = append(settingsOrder, id)
		}
	}

	extMap := getExtBaseMap()
	// 65037 ech
	if config.Ech {
		extMap[tls.ExtensionECH] = &tls.GREASEEncryptedClientHelloExtension{
			CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_AES_128_GCM,
				},
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_CHACHA20_POLY1305,
				},
			},
			CandidatePayloadLens: []uint16{128, 160, 192, 224},
		}
	}
	// 21 padding
	if config.TlsPadding {
		extMap[tls.ExtensionPadding] = &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}
	}

	// 34 for firefox
	var mappedDelegatedCredentialsAlgorithms []tls.SignatureScheme
	if config.TlsDelegatedCredentials != "" {
		for _, del := range strings.Split(config.TlsDelegatedCredentials, ",") {
			delegatedCredentialsAlgorithm, ok := delegatedCredentialsAlgorithms[del]
			if ok {
				mappedDelegatedCredentialsAlgorithms = append(mappedDelegatedCredentialsAlgorithms, delegatedCredentialsAlgorithm)
			} else {
				supportedDelegatedCredentialsAlgorithmAsUint, err := strconv.ParseUint(del, 16, 16)

				if err != nil {
					return profile, fmt.Errorf("%s is not a valid supportedDelegatedCredentialsAlgorithm", del)
				}

				mappedDelegatedCredentialsAlgorithms = append(mappedDelegatedCredentialsAlgorithms, tls.SignatureScheme(uint16(supportedDelegatedCredentialsAlgorithmAsUint)))
			}
		}
		if len(mappedDelegatedCredentialsAlgorithms) > 0 {
			extMap[tls.ExtensionDelegatedCredentials] = &tls.DelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: mappedDelegatedCredentialsAlgorithms,
			}
		}
	}
	// 28 for firefox share limit
	if config.TlsRecordSizeLimit != 0 {
		extMap[tls.ExtensionRecordSizeLimit] = &tls.FakeRecordSizeLimitExtension{
			Limit: uint16(config.TlsRecordSizeLimit),
		}
	}
	// 43 tls version
	var tlsExtensionVersion = tls.SupportedVersionsExtension{}
	switch config.TlsVersion {
	case "any":
		clientHelloSpec.TLSVersMax = tls.VersionTLS13
		clientHelloSpec.TLSVersMin = tls.VersionTLS10
		tlsExtensionVersion.Versions = []uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
			tls.VersionTLS11,
			tls.VersionTLS10,
		}
	case "1.3":
		clientHelloSpec.TLSVersMax = tls.VersionTLS13
		clientHelloSpec.TLSVersMin = tls.VersionTLS12
		tlsExtensionVersion.Versions = []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
		}
	case "1.2":
		clientHelloSpec.TLSVersMax = tls.VersionTLS12
		clientHelloSpec.TLSVersMin = tls.VersionTLS11
		tlsExtensionVersion.Versions = []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS12,
			tls.VersionTLS11,
		}
	case "1.1":
		clientHelloSpec.TLSVersMax = tls.VersionTLS11
		clientHelloSpec.TLSVersMin = tls.VersionTLS10
		tlsExtensionVersion.Versions = []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS11,
			tls.VersionTLS10,
		}
	default:
		return profile, fmt.Errorf("ja3Str tls version error")
	}
	extMap[tls.ExtensionSupportedVersions] = &tlsExtensionVersion

	// 51 key share
	var curvesParts = strings.Split(config.Curves, ":")
	var keyShareCurves = []tls.KeyShare{}
	if config.TlsGrease {
		keyShareCurves = append(keyShareCurves, tls.KeyShare{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}})
	}
	var keyShareLimit = 3
	if config.TlsKeySharesLimit > 0 {
		keyShareLimit = config.TlsKeySharesLimit
	}
	if keyShareLimit > len(curvesParts) {
		return profile, fmt.Errorf("keyShareLimit is too large")
	}

	var keyShareCurvesParts = curvesParts[:keyShareLimit-1]
	for _, c := range keyShareCurvesParts {
		cid, ok := curves[c]
		if !ok {
			return profile, fmt.Errorf("don't support this curve: %s ", c)
		}
		keyShareCurves = append(keyShareCurves, tls.KeyShare{Group: cid})
	}
	extMap[tls.ExtensionKeyShare] = &tls.KeyShareExtension{KeyShares: keyShareCurves}

	// 11 end of parts , default "0"
	var targetPointFormats []byte
	pid, err := strconv.ParseUint("0", 10, 8)
	if err != nil {
		return profile, err
	}
	targetPointFormats = append(targetPointFormats, byte(pid))
	extMap[tls.ExtensionSupportedPoints] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// 10 Curves part 3
	var targetCurves []tls.CurveID

	for _, c := range curvesParts {
		cid, ok := curves[c]
		if !ok {
			return profile, fmt.Errorf("don't support this curve: %s ", c)
		}
		// cid, err := strconv.ParseUint(id, 10, 16)
		// if err != nil {
		// 	return profile, err
		// }
		targetCurves = append(targetCurves, cid)
	}
	extMap[tls.ExtensionSupportedCurves] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	// 27 CertCompression
	var certCompressionAlgo []tls.CertCompressionAlgo
	for _, e := range strings.Split(config.CertCompression, ",") {
		cert, ok := certCompression[e]
		if !ok {
			return profile, fmt.Errorf("don't support this certCompression: %s ", e)
		}
		certCompressionAlgo = append(certCompressionAlgo, cert)
	}
	extMap[tls.ExtensionCompressCertificate] = &tls.UtlsCompressCertExtension{Algorithms: certCompressionAlgo}

	// 17513 alps
	if config.ALPSO {
		extMap[tls.ExtensionALPS] = &tls.ApplicationSettingsExtension{
			CodePoint:          tls.ExtensionALPSOld,
			SupportedProtocols: []string{"h2"},
		}
	}
	// 17613 alps old
	if config.ALPS {
		extMap[tls.ExtensionALPS] = &tls.ApplicationSettingsExtension{
			CodePoint:          tls.ExtensionALPS,
			SupportedProtocols: []string{"h2"},
		}
	}
	if config.ALPSS {
		extMap[tls.ExtensionALPN] = &tls.ALPNExtension{AlpnProtocols: []string{"http/1.1", "h2"}}
	}

	// 13 signature algorithms
	var SignatureHashed = "ECDSAWithP256AndSHA256,PSSWithSHA256,PKCS1WithSHA256,ECDSAWithP384AndSHA384,PSSWithSHA384,PKCS1WithSHA384,PSSWithSHA512,PKCS1WithSHA512"
	if config.SignatureHashed != "" {
		SignatureHashed = config.SignatureHashed
	}
	var mapSignatureAlgorithms []tls.SignatureScheme
	for _, supportedSignatureAlgorithm := range strings.Split(SignatureHashed, ",") {
		signatureAlgorithm, ok := signatureAlgorithms[supportedSignatureAlgorithm]
		if ok {
			mapSignatureAlgorithms = append(mapSignatureAlgorithms, signatureAlgorithm)
		} else {
			supportedSignatureAlgorithmAsUint, err := strconv.ParseUint(supportedSignatureAlgorithm, 16, 16)

			if err != nil {
				return profile, fmt.Errorf("%s is not a valid supportedSignatureAlgorithm", supportedSignatureAlgorithm)
			}

			mapSignatureAlgorithms = append(mapSignatureAlgorithms, tls.SignatureScheme(uint16(supportedSignatureAlgorithmAsUint)))
		}
	}
	if len(mapSignatureAlgorithms) == 0 {
		return profile, fmt.Errorf("no supportedSignatureAlgorithm")
	}
	extMap[tls.ExtensionSignatureAlgorithms] = &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: mapSignatureAlgorithms}

	// the end of extMap
	//
	// ext part 2
	var exts []tls.TLSExtension
	if config.TlsExtensionOrder != "" {
		for _, e := range strings.Split(config.TlsExtensionOrder, "-") {
			eId, err := strconv.ParseUint(e, 10, 16)
			if err != nil {
				return profile, err
			}
			te, ok := extMap[uint16(eId)]
			if !ok {
				return profile, fmt.Errorf("don't support this ext: %s ", e)
			}

			exts = append(exts, te)
		}
	} else {
		for _, e := range extMap {
			exts = append(exts, e)
		}
		if config.TlsGrease {
			exts = append([]tls.TLSExtension{&tls.UtlsGREASEExtension{}}, exts...)
			exts = append(exts, &tls.UtlsGREASEExtension{})
		}
	}

	clientHelloSpec.Extensions = exts
	clientHelloSpec.GetSessionID = sha256.Sum256

	clientHelloId := tls.ClientHelloID{
		Client:               config.Client,
		RandomExtensionOrder: config.RandomExtensionOrder,
		Version:              config.Version,
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return clientHelloSpec, nil
		},
	}

	ph := "masp"
	pseudoHeaderOrder := []string{}
	if config.Http2PseudoHeaderOrder != "" {
		ph = config.Http2PseudoHeaderOrder
	}
	phMap := strings.Split(ph, "")
	for _, ph := range phMap {
		pseudo, exist := pseudoHeader[ph]
		if !exist {
			return profile, fmt.Errorf("don't support this pseudoHeader: %s ", ph)
		}
		pseudoHeaderOrder = append(pseudoHeaderOrder, (pseudo))
	}
	StreamDep := 0
	if config.Http2StreamDep > 0 {
		StreamDep = config.Http2StreamDep
	}
	headerPriority := &http2.PriorityParam{
		StreamDep: uint32(StreamDep),
		Exclusive: config.Http2StreamExclusive == 1,
		Weight:    uint8(config.Http2StreamWight),
	}
	priorities := []http2.Priority{}
	if config.Http2Priorities != "" {
		for _, p := range strings.Split(config.Http2Priorities, ",") {
			pParts := strings.Split(p, ":")
			if len(pParts) != 4 {
				return profile, fmt.Errorf("don't support this http2Priorities: %s ", p)
			}
			sid, err := strconv.ParseUint(pParts[0], 10, 32)
			if err != nil {
				return profile, err
			}
			priority := http2.Priority{}
			priority.StreamID = uint32(sid)

			dep, err := strconv.ParseUint(pParts[1], 10, 32)
			if err != nil {
				return profile, err
			}

			weight, err := strconv.ParseUint(pParts[3], 10, 8)
			if err != nil {
				return profile, err
			}

			priority.PriorityParam = http2.PriorityParam{
				StreamDep: uint32(dep),
				Exclusive: pParts[2] == "1",
				Weight:    uint8(weight),
			}
			priorities = append(priorities, priority)
		}
	}
	return ClientProfile{
		ClientHelloId:     clientHelloId,
		Settings:          settings,
		SettingsOrder:     settingsOrder,
		PseudoHeaderOrder: pseudoHeaderOrder,
		ConnectionFlow:    config.Http2WindowUpdate,
		Priorities:        priorities,
		HeaderPriority:    headerPriority,
	}, nil
}
