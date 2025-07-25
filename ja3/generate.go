package ja3

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/smallerqiu/ja3-client/http2"
	"github.com/smallerqiu/ja3-client/util"
	tls "github.com/smallerqiu/utls"
)

func getExtBaseMap() map[uint16]tls.TLSExtension {
	return map[uint16]tls.TLSExtension{
		tls.ExtensionServerName:           &tls.SNIExtension{},
		tls.ExtensionStatusRequest:        &tls.StatusRequestExtension{},
		tls.ExtensionALPN:                 &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		tls.ExtensionSCT:                  &tls.SCTExtension{},
		tls.ExtensionExtendedMasterSecret: &tls.ExtendedMasterSecretExtension{},
		tls.ExtensionSessionTicket:        &tls.SessionTicketExtension{},
		tls.ExtensionPSKModes:             &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		tls.ExtensionRenegotiationInfo: &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}
}

func getExtExtraMap() map[uint16]tls.TLSExtension {
	return map[uint16]tls.TLSExtension{
		// important....
		tls.ExtensionSignatureAlgorithms: &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
		tls.ExtensionStatusRequestV2:  &tls.GenericExtension{Id: 17}, //status_request_v2
		tls.ExtensionPadding:          &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		tls.ExtensionEncryptThenMac:   &tls.GenericExtension{Id: 22},
		tls.ExtensionFakeTokenBinding: &tls.FakeTokenBindingExtension{},
		tls.ExtensionCompressCertificate: &tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
			tls.CertCompressionBrotli,
		}},
		tls.ExtensionRecordSizeLimit: &tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
		tls.ExtensionDelegatedCredentials: &tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.ECDSAWithSHA1,
		}},
		tls.ExtensionPreSharedKey: &tls.UtlsPreSharedKeyExtension{},
		tls.ExtensionEarlyData:    &tls.GenericExtension{Id: tls.ExtensionEarlyData},
		tls.ExtensionSupportedVersions: &tls.SupportedVersionsExtension{
			Versions: []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12},
		},
		tls.ExtensionCookie:            &tls.CookieExtension{},
		tls.ExtensionPostHandShakeAuth: &tls.GenericExtension{Id: 49},
		tls.ExtensionSignatureAlgorithmsCert: &tls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.SignatureScheme(0x0806),
				tls.SignatureScheme(0x0601),
			},
		},
		tls.ExtensionQUICTransportParameters: &tls.QUICTransportParametersExtension{},
		tls.ExtensionNextProtoNeg:            &tls.NPNExtension{},
		tls.ExtensionALPSOld: &tls.ApplicationSettingsExtension{
			CodePoint:          tls.ExtensionALPSOld,
			SupportedProtocols: []string{"h2"},
		},
		tls.ExtensionALPS: &tls.ApplicationSettingsExtension{
			CodePoint:          tls.ExtensionALPS,
			SupportedProtocols: []string{"h2"},
		},
		tls.ExtensionECH: tls.BoringGREASEECH(), //ech
		// tls.ExtensionRenegotiationInfo: &tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		tls.ExtensionChannelId: &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}, //FIXME
	}
}

func buildHttp2Spec(akamai_text string) (profile ClientProfile, err error) {
	akamaiMap := strings.Split(akamai_text, "|")
	if len(akamaiMap) < 4 {
		return profile, errors.New("ja3 format error")
	}
	var settings = map[http2.SettingID]uint32{}
	var settingsOrder []http2.SettingID
	for _, s := range strings.Split(akamaiMap[0], ";") {
		s := strings.Split(s, ":")
		if len(s) != 2 {
			return profile, fmt.Errorf("invalid http2 setting: %s", s)
		}
		id, ok := H2SettingsOrder[s[0]]
		if !ok {
			return profile, fmt.Errorf("invalid http2 setting order: %s", s[0])
		}
		idStr := s[1]
		idUint, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			return profile, fmt.Errorf("failed to parse extension ID: %v", err)
		}
		settings[id] = uint32(idUint)
		settingsOrder = append(settingsOrder, id)
	}
	profile.Settings = settings
	profile.SettingsOrder = settingsOrder
	flow, err := strconv.ParseUint(akamaiMap[1], 10, 32)
	if err != nil {
		return profile, fmt.Errorf("failed to parse connection flow: %v", err)
	}
	profile.ConnectionFlow = uint32(flow)

	prioritiesMap := akamaiMap[2]
	if prioritiesMap != "0" {
		priorities := []http2.Priority{}
		for _, p := range strings.Split(prioritiesMap, ",") {
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
		profile.Priorities = priorities
	}
	pseudoHeaderOrder := []string{}
	pseudoMap := strings.Split(akamaiMap[3], ",")
	if len(pseudoMap) != 4 {
		return profile, fmt.Errorf("don't support this pseudo: %s ", pseudoMap)
	}
	for _, pseudo := range pseudoMap {
		pseudo, exist := pseudoHeader[pseudo]
		if !exist {
			return profile, fmt.Errorf("don't support this pseudoHeader: %s ", pseudo)
		}
		pseudoHeaderOrder = append(pseudoHeaderOrder, (pseudo))
	}
	profile.PseudoHeaderOrder = pseudoHeaderOrder

	return profile, nil
}

func BuildClientHelloSpec(impersonate string) (profile ClientProfile, err error) {
	config, ok := MappedTLSClients[impersonate]
	if !ok {
		log.Printf("the input client %v don't support, so use default %v", impersonate, DefaultImpersonate)
		config = DefaultClient
	}
	return BuildClientHelloSpecWithCP(config)
}

func BuildClientHelloSpecWithCP(config ClientData) (profile ClientProfile, err error) {

	var clientHelloSpec tls.ClientHelloSpec
	// ciphers part 1
	var ciphers = []uint16{}
	// if grease is true, so the extension is to use grease twice.
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

	extMap := getExtBaseMap()
	// for safari
	if config.NoTlsSessionTicket {
		delete(extMap, tls.ExtensionSessionTicket)
	}
	// ech
	if config.Ech {
		extMap[tls.ExtensionECH] = tls.BoringGREASEECH()
	}
	// padding
	if config.TlsPadding {
		extMap[tls.ExtensionPadding] = &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}
	}

	// for firefox
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
	// for firefox share limit
	if config.TlsRecordSizeLimit != 0 {
		extMap[tls.ExtensionRecordSizeLimit] = &tls.FakeRecordSizeLimitExtension{
			Limit: uint16(config.TlsRecordSizeLimit),
		}
	}
	// tls version
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

	// key share
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

	// Curves part 3
	var targetCurves []tls.CurveID
	if config.TlsGrease {
		targetCurves = append(targetCurves, tls.CurveID(tls.GREASE_PLACEHOLDER))
	}
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

	// CertCompression
	if config.CertCompression != "" {
		var certCompressionAlgo []tls.CertCompressionAlgo
		for _, e := range strings.Split(config.CertCompression, ",") {
			cert, ok := certCompression[e]
			if !ok {
				return profile, fmt.Errorf("don't support this certCompression: %s ", e)
			}
			certCompressionAlgo = append(certCompressionAlgo, cert)
		}
		extMap[tls.ExtensionCompressCertificate] = &tls.UtlsCompressCertExtension{Algorithms: certCompressionAlgo}
	}

	// alps
	if config.ALPSO {
		extMap[tls.ExtensionALPSOld] = &tls.ApplicationSettingsExtension{
			CodePoint:          tls.ExtensionALPSOld,
			SupportedProtocols: []string{"h2"},
		}
	}
	// alps old
	if config.ALPS {
		extMap[tls.ExtensionALPS] = &tls.ApplicationSettingsExtension{
			CodePoint:          tls.ExtensionALPS,
			SupportedProtocols: []string{"h2"},
		}
	}
	if config.ALPSS {
		// cause ja4 like t13xxh1 ,should be t13xxh2
		extMap[tls.ExtensionALPN] = &tls.ALPNExtension{AlpnProtocols: []string{"http/1.1", "h2"}}
	}

	// signature algorithms
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

	// end of parts , default "0"
	var targetPointFormats []byte
	pid, err := strconv.ParseUint("0", 10, 8)
	if err != nil {
		return profile, err
	}
	targetPointFormats = append(targetPointFormats, byte(pid))
	extMap[tls.ExtensionSupportedPoints] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

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
	akamaiMap := []string{}
	akamaiMap = append(akamaiMap, config.Http2Setting)
	akamaiMap = append(akamaiMap, strconv.FormatUint(uint64(config.Http2WindowUpdate), 10))
	if config.Http2Priorities != "" {
		akamaiMap = append(akamaiMap, config.Http2Priorities)
	} else {
		akamaiMap = append(akamaiMap, "0")
	}
	pseudo := "masp"
	if config.Http2PseudoHeaderOrder != "" {
		pseudo = config.Http2PseudoHeaderOrder
	}
	pseudoMap := strings.Join(strings.Split(pseudo, ""), ",")
	akamaiMap = append(akamaiMap, pseudoMap)

	http2Config, err := buildHttp2Spec(strings.Join(akamaiMap, "|"))
	if err != nil {
		return profile, err
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

	return ClientProfile{
		UserAgent:         config.UserAgent,
		ClientHelloId:     clientHelloId,
		Settings:          http2Config.Settings,
		SettingsOrder:     http2Config.SettingsOrder,
		PseudoHeaderOrder: http2Config.PseudoHeaderOrder,
		ConnectionFlow:    config.Http2WindowUpdate,
		Priorities:        http2Config.Priorities,
		HeaderPriority:    headerPriority,
	}, nil
}

// ja3key as the tls finger , akamai_text as the http2 finger
// In theory, it’s not possible to reverse-infer solely from the JA3 key,
// because the information is not complete — it can only be roughly reconstructed.
func BuildClientHelloSpecFromJa3Key(ja3key string, akamai_text string) (profile ClientProfile, err error) {
	ja3StringParts := strings.Split(ja3key, ",")
	if len(ja3StringParts) < 4 {
		return profile, errors.New("ja3 format error")
	}
	extMap := getExtBaseMap()

	var clientHelloSpec tls.ClientHelloSpec
	// tls version part 0

	// password part 1
	ciphers := strings.Split(ja3StringParts[1], "-")
	var cipherSuite []uint16
	// default Grease
	cipherSuite = append(cipherSuite, uint16(tls.GREASE_PLACEHOLDER))
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return profile, err
		}
		cipherSuite = append(cipherSuite, uint16(cid))
	}
	clientHelloSpec.CipherSuites = cipherSuite
	clientHelloSpec.CompressionMethods = []byte{tls.CompressionNone}

	// !!! 13 This part cannot be reversed, so strictly speaking, it is not accurate and can only be roughly inferred.
	// The direct impact is that the ja4 value cannot approximate that of a real browser.
	// However, it can still bypass Cloudflare. That's the best i can do.
	// so, all i can say wocao.
	// var signature = []tls.SignatureScheme{}
	// extMap[tls.ExtensionSignatureAlgorithms] = &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: signature}

	// curves part 3
	mapCurves := strings.Split(ja3StringParts[3], "-")
	if len(curves) == 1 && mapCurves[0] == "" {
		mapCurves = []string{}
	}
	var targetCurves []tls.CurveID
	var keyShareCurves = []tls.KeyShare{}
	keyShareCurves = append(keyShareCurves, tls.KeyShare{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}})
	limit := 0
	for _, c := range mapCurves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return profile, err
		}
		if limit < 2 {
			keyShareCurves = append(keyShareCurves, tls.KeyShare{Group: tls.CurveID(cid)})
			limit = limit + 1
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	extMap[tls.ExtensionSupportedCurves] = &tls.SupportedCurvesExtension{Curves: targetCurves}
	extMap[tls.ExtensionKeyShare] = &tls.KeyShareExtension{KeyShares: keyShareCurves}

	// part 4
	var targetPointFormats []byte
	pid, err := strconv.ParseUint("0", 10, 8)
	if err != nil {
		return profile, err
	}
	targetPointFormats = append(targetPointFormats, byte(pid))
	extMap[tls.ExtensionSupportedPoints] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// end
	var exts []tls.TLSExtension

	extExtraMap := getExtExtraMap()
	for pid, ext := range extExtraMap {
		extMap[pid] = ext
	}

	// part 2
	extensions := strings.Split(ja3StringParts[2], "-")
	for _, e := range extensions {
		eId, err := strconv.ParseUint(e, 10, 16)
		if err != nil {
			return ClientProfile{}, err
		}
		te, ok := extMap[uint16(eId)]
		if !ok {
			return ClientProfile{}, fmt.Errorf("don't support this ext: %s ", e)
		}

		exts = append(exts, te)
	}
	// default grease opened.
	exts = append([]tls.TLSExtension{&tls.UtlsGREASEExtension{}}, exts...)
	exts = append(exts, &tls.UtlsGREASEExtension{})

	clientHelloSpec.Extensions = exts
	clientHelloSpec.GetSessionID = sha256.Sum256
	clientHelloSpec.TLSVersMax = tls.VersionTLS13
	clientHelloSpec.TLSVersMin = tls.VersionTLS12
	// latest part 0
	clientHelloId := tls.ClientHelloID{
		RandomExtensionOrder: false,
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return clientHelloSpec, nil
		},
	}

	if akamai_text == "" {
		akamai_text = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	}

	http2Config, err := buildHttp2Spec(akamai_text)
	if err != nil {
		return profile, err
	}

	return ClientProfile{
		UserAgent:         DefaultClient.UserAgent,
		ClientHelloId:     clientHelloId,
		Settings:          http2Config.Settings,
		SettingsOrder:     http2Config.SettingsOrder,
		PseudoHeaderOrder: http2Config.PseudoHeaderOrder,
		ConnectionFlow:    http2Config.ConnectionFlow,
		Priorities:        http2Config.Priorities,
		HeaderPriority:    http2Config.HeaderPriority,
	}, nil
}
