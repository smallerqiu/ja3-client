package ja3_client

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/smallerqiu/ja3-client/browser"
	"github.com/smallerqiu/ja3-client/http2"
	tls "github.com/smallerqiu/utls"
)

var (
	Firefox  = "Firefox"
	QQ       = "QQ Browser"
	QQMobile = "QQ Browser Mobile"
	IOS      = "Mobile Safari"
	Safari   = "Safari"
	Xiaomi   = "MiuiBrowser"
	Samsung  = "Samsung Internet"
	UC       = "UC Browser"
	Opera    = "Opera"
	Edge     = "Edge"
	Chrome   = "Chrome"
	QH360    = "360"
)

type CandidateCipherSuites struct {
	KdfId  string
	AeadId string
}

func buildClientHelloSpec(config ClientData) (profile browser.ClientProfile, err error) {
	// 771
	// 4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53
	// 23-27-5-45-13-11-18-17613-16-65281-43-51-65037-35-0-10
	// 4588-29-23-24
	// 0

	var clientHelloSpec tls.ClientHelloSpec
	// ciphers part 1
	var ciphers = []uint16{}
	for _, cipher := range allToLower(config.cipherSuites) {
		cipherId, ok := CipherSuites[cipher]
		if ok {
			ciphers = append(ciphers, cipherId)
		} else {
			return profile, fmt.Errorf("cipher not found: %s", cipher)
		}
	}
	clientHelloSpec.CipherSuites = ciphers
	if config.compressed {
		clientHelloSpec.CompressionMethods = []byte{tls.CompressionNone}
	}
	// setting
	var settings = map[http2.SettingID]uint32{}
	var settingsOrder []http2.SettingID
	if config.http2Setting != "" {
		for _, s := range strings.Split(config.http2Setting, ";") {
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
			settings = map[http2.SettingID]uint32{
				id: uint32(idUint),
			}
			settingsOrder = append(settingsOrder, id)
		}
	}

	extMap := getExtensionBaseMap()

	// ext part 2
	var exts []tls.TLSExtension
	if len(config.tlsExtensionOrder) == 0 {
		return profile, fmt.Errorf("tlsExtensionOrder is empty")
	}

	for _, e := range config.tlsExtensionOrder {
		eId, err := strconv.ParseUint(e, 10, 16)
		if err != nil {
			return profile, err
		}
		te, ok := extMap[uint16(eId)]
		if !ok {
			return profile, fmt.Errorf("don't suport this ext: %s ", e)
		}

		exts = append(exts, te)
	}

	// Curves part 3
	var targetCurves []tls.CurveID

	for _, c := range config.curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return profile, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	extMap[tls.ExtensionSupportedCurves] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	clientHelloSpec.Extensions = exts
	clientHelloSpec.GetSessionID = sha256.Sum256

	clientHelloId := tls.ClientHelloID{
		Client:               config.client,
		RandomExtensionOrder: config.randomExtensionOrder,
		Version:              config.version,
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return clientHelloSpec, nil
		},
	}

	return browser.ClientProfile{
		clientHelloId:     clientHelloId,
		settings:          settings,
		settingsOrder:     settingsOrder,
		pseudoHeaderOrder: pseudoHeaderOrder,
		connectionFlow:    connectionFlow,
		priorities:        priorities,
		headerPriority:    headerPriority,
	}, nil
}

func getExtensionExtraMap(extMap map[uint16]tls.TLSExtension) {

}

func FormatJa3(ja3 string, browserType string, version string, randomExtensionOrder bool) (pfile browser.ClientProfile, err error) {
	extMap := getExtensionBaseMap()
	ja3StringParts := strings.Split(ja3, ",")
	if len(ja3StringParts) < 4 {
		return pfile, errors.New("ja3 format error")
	}
	// 1. 密码
	ciphers := strings.Split(ja3StringParts[1], "-")
	var suites []uint16
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return pfile, err
		}
		suites = append(suites, uint16(cid))
	}

	// 3. 曲线
	mapCurves := strings.Split(ja3StringParts[3], "-")
	if len(curves) == 1 && mapCurves[0] == "" {
		mapCurves = []string{}
	}
	var targetCurves []tls.CurveID
	for _, c := range mapCurves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return pfile, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	// 10
	extMap[tls.ExtensionSupportedCurves] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	// 4. 点格式
	pointFormats := strings.Split(ja3StringParts[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}

	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return pfile, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	// 11
	extMap[tls.ExtensionSupportedPoints] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	//end
	profile := getClientProfile(browserType)

	// 补充浏览器特性
	// 13
	var mapSignatureAlgorithms []tls.SignatureScheme
	for _, supportedSignatureAlgorithm := range profile.supportedSignatureAlgorithms {
		signatureAlgorithm, ok := signatureAlgorithms[supportedSignatureAlgorithm]
		if ok {
			mapSignatureAlgorithms = append(mapSignatureAlgorithms, signatureAlgorithm)
		} else {
			supportedSignatureAlgorithmAsUint, err := strconv.ParseUint(supportedSignatureAlgorithm, 16, 16)

			if err != nil {
				return pfile, fmt.Errorf("%s is not a valid supportedSignatureAlgorithm", supportedSignatureAlgorithm)
			}

			mapSignatureAlgorithms = append(mapSignatureAlgorithms, tls.SignatureScheme(uint16(supportedSignatureAlgorithmAsUint)))
		}
	}
	extMap[tls.ExtensionSignatureAlgorithms] = &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: mapSignatureAlgorithms}

	// 16
	extMap[tls.ExtensionALPN] = &tls.ALPNExtension{AlpnProtocols: profile.supportedProtocolsALPN}
	// extMap[tls.ExtensionALPN] = &tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}}
	//
	// 34 firefox 独有特性
	var mappedDelegatedCredentialsAlgorithms []tls.SignatureScheme
	for _, supportedDelegatedCredentialsAlgorithm := range profile.supportedDelegatedCredentialsAlgorithms {
		delegatedCredentialsAlgorithm, ok := delegatedCredentialsAlgorithms[supportedDelegatedCredentialsAlgorithm]
		if ok {
			mappedDelegatedCredentialsAlgorithms = append(mappedDelegatedCredentialsAlgorithms, delegatedCredentialsAlgorithm)
		} else {
			supportedDelegatedCredentialsAlgorithmAsUint, err := strconv.ParseUint(supportedDelegatedCredentialsAlgorithm, 16, 16)

			if err != nil {
				return pfile, fmt.Errorf("%s is not a valid supportedDelegatedCredentialsAlgorithm", supportedDelegatedCredentialsAlgorithm)
			}

			mappedDelegatedCredentialsAlgorithms = append(mappedDelegatedCredentialsAlgorithms, tls.SignatureScheme(uint16(supportedDelegatedCredentialsAlgorithmAsUint)))
		}
	}
	extMap[tls.ExtensionDelegatedCredentials] = &tls.DelegatedCredentialsExtension{
		SupportedSignatureAlgorithms: mappedDelegatedCredentialsAlgorithms,
	}
	// 43 tls 版本 , 已知bug , 这里不能使用浏览器直接特性
	// var mappedTlsVersions []uint16
	// for _, version := range profile.supportedVersions {
	// 	mappedVersion, ok := tlsVersions[version]
	// 	if ok {
	// 		mappedTlsVersions = append(mappedTlsVersions, mappedVersion)
	// 	}
	// }
	// extMap[tls.ExtensionSupportedVersions] = &tls.SupportedVersionsExtension{Versions: mappedTlsVersions}

	// 43 tls 版本 772 不支持, bug ,会造成304 错误
	tlsVersion := ja3StringParts[0]
	ver, err := strconv.ParseUint(tlsVersion, 10, 16)
	if err != nil {
		return pfile, err
	}
	tlsMaxVersion, tlsMinVersion, tlsExtension, err := createTlsVersion(uint16(ver))
	if err != nil {
		return pfile, err
	}
	extMap[tls.ExtensionSupportedVersions] = tlsExtension

	//51 keyshare
	var mappedKeyShares []tls.KeyShare
	for _, keyShareCurve := range profile.keyShareCurves {
		resolvedKeyShare, ok := curves[keyShareCurve]
		if !ok {
			continue
		}
		mappedKeyShare := tls.KeyShare{Group: resolvedKeyShare}
		if keyShareCurve == "GREASE" {
			mappedKeyShare.Data = []byte{0}
		}
		mappedKeyShares = append(mappedKeyShares, mappedKeyShare)
	}
	extMap[tls.ExtensionKeyShare] = &tls.KeyShareExtension{KeyShares: mappedKeyShares}

	// 65037 部分浏览器才支持的扩展
	var mappedHpkeSymmetricCipherSuites []tls.HPKESymmetricCipherSuite

	for _, echCandidateCipherSuites := range profile.echCandidateCipherSuites {
		kdfId, ok1 := kdfIds[echCandidateCipherSuites.KdfId]

		aeadId, ok2 := aeadIds[echCandidateCipherSuites.AeadId]
		if ok1 && ok2 {
			mappedHpkeSymmetricCipherSuites = append(mappedHpkeSymmetricCipherSuites, tls.HPKESymmetricCipherSuite{
				KdfId:  kdfId,
				AeadId: aeadId,
			})
		} else {
			kdfId, err := strconv.ParseUint(echCandidateCipherSuites.KdfId, 16, 16)
			if err != nil {
				return browser.ClientProfile{}, fmt.Errorf("%s is not a valid KdfId", echCandidateCipherSuites.KdfId)
			}

			aeadId, err := strconv.ParseUint(echCandidateCipherSuites.AeadId, 16, 16)
			if err != nil {
				return browser.ClientProfile{}, fmt.Errorf("%s is not a valid aeadId", echCandidateCipherSuites.AeadId)
			}

			mappedHpkeSymmetricCipherSuites = append(mappedHpkeSymmetricCipherSuites, tls.HPKESymmetricCipherSuite{
				KdfId:  uint16(kdfId),
				AeadId: uint16(aeadId),
			})
		}
	}
	extMap[tls.ExtensionECH] = &tls.GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: mappedHpkeSymmetricCipherSuites,
		CandidatePayloadLens:  profile.candidatePayloads,
	}

	// 27 压缩类型
	compressionAlgo, ok := certCompression[profile.certCompressionAlgo]
	if !ok && strings.Contains(ja3StringParts[2], fmt.Sprintf("%d", tls.ExtensionCompressCertificate)) {
		fmt.Println("attention our ja3 defines ExtensionCompressCertificate but you did not specify certCompression")
	}
	if certCompression != nil {
		extMap[tls.ExtensionCompressCertificate] = &tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{compressionAlgo}}
	}

	// 50 支持加密类型
	extMap[tls.ExtensionSignatureAlgorithmsCert] = &tls.SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: mapSignatureAlgorithms,
	}

	// 17513
	extMap[tls.ExtensionALPSOld] = &tls.ApplicationSettingsExtension{
		CodePoint:          tls.ExtensionALPSOld,
		SupportedProtocols: profile.supportedProtocolsALPS,
	}

	// 17613
	extMap[tls.ExtensionALPS] = &tls.ApplicationSettingsExtension{
		CodePoint:          tls.ExtensionALPS,
		SupportedProtocols: profile.supportedProtocolsALPS,
	}

	// 2. 扩展
	extensions := strings.Split(ja3StringParts[2], "-")
	var exts []tls.TLSExtension
	for _, e := range extensions {
		eId, err := strconv.ParseUint(e, 10, 16)
		if err != nil {
			return browser.ClientProfile{}, err
		}
		te, ok := extMap[uint16(eId)]
		if !ok {
			return browser.ClientProfile{}, fmt.Errorf("don't suport this ext: %s ", e)
		}

		exts = append(exts, te)
	}
	return browser.NewClientProfile(tls.ClientHelloID{
			Client:               browserType,
			RandomExtensionOrder: randomExtensionOrder,
			Version:              version,
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					TLSVersMin:         tlsMinVersion,
					TLSVersMax:         tlsMaxVersion,
					CipherSuites:       suites,
					CompressionMethods: []byte{0},
					Extensions:         exts,
					GetSessionID:       sha256.Sum256,
				}, nil

			},
		},
			profile.settings,
			profile.settingsOrder,
			profile.pseudoHeaderOrder,
			profile.connectionFlow,
			profile.priorities,
			profile.headerPriority),
		nil
}

func createTlsVersion(ver uint16) (tlsMaxVersion uint16, tlsMinVersion uint16, tlsSuppor tls.TLSExtension, err error) {
	switch ver {
	case tls.VersionTLS13:
		tlsMaxVersion = tls.VersionTLS13
		tlsMinVersion = tls.VersionTLS12
		tlsSuppor = &tls.SupportedVersionsExtension{
			Versions: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
			},
		}
	case tls.VersionTLS12:
		tlsMaxVersion = tls.VersionTLS12
		tlsMinVersion = tls.VersionTLS11
		tlsSuppor = &tls.SupportedVersionsExtension{
			Versions: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS12,
				tls.VersionTLS11,
			},
		}
	case tls.VersionTLS11:
		tlsMaxVersion = tls.VersionTLS11
		tlsMinVersion = tls.VersionTLS10
		tlsSuppor = &tls.SupportedVersionsExtension{
			Versions: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS11,
				tls.VersionTLS10,
			},
		}
	default:
		err = errors.New("ja3Str tls version error")
	}
	return
}
func getExtensionBaseMap() map[uint16]tls.TLSExtension {
	return map[uint16]tls.TLSExtension{
		// This extension needs to be instantiated every time and not be reused if it occurs multiple times in the same ja3
		//tls.GREASE_PLACEHOLDER:     &tls.UtlsGREASEExtension{},

		// 0
		tls.ExtensionServerName: &tls.SNIExtension{},
		//5
		tls.ExtensionStatusRequest: &tls.StatusRequestExtension{},

		// These are applied later
		// tls.ExtensionSupportedCurves: &tls.SupportedCurvesExtension{...}
		// tls.ExtensionSupportedPoints: &tls.SupportedPointsExtension{...}
		// tls.ExtensionSignatureAlgorithms: &tls.SignatureAlgorithmsExtension{...}
		// tls.ExtensionCompressCertificate:  &tls.UtlsCompressCertExtension{...},
		// tls.ExtensionSupportedVersions: &tls.SupportedVersionsExtension{...}
		// tls.ExtensionKeyShare:     &tls.KeyShareExtension{...},
		// tls.ExtensionDelegatedCredentials: &tls.DelegatedCredentialsExtension{},
		// tls.ExtensionALPN: &tls.ALPNExtension{},
		// tls.ExtensionALPS:         &tls.ApplicationSettingsExtension{},
		// 17
		tls.ExtensionStatusRequestV2: &tls.GenericExtension{Id: 17}, //status_request_v2
		// 18
		tls.ExtensionSCT: &tls.SCTExtension{},
		// 21
		tls.ExtensionPadding: &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		// 22
		tls.ExtensionEncryptThenMac: &tls.GenericExtension{Id: 22}, //status_request_v2
		// 23
		tls.ExtensionExtendedMasterSecret: &tls.ExtendedMasterSecretExtension{},
		// 24
		tls.ExtensionFakeTokenBinding: &tls.FakeTokenBindingExtension{},
		// 28
		tls.ExtensionRecordSizeLimit: &tls.FakeRecordSizeLimitExtension{},
		// 35
		tls.ExtensionSessionTicket: &tls.SessionTicketExtension{},
		// 41
		tls.ExtensionPreSharedKey: &tls.UtlsPreSharedKeyExtension{},
		// 42
		tls.ExtensionEarlyData: &tls.GenericExtension{Id: tls.ExtensionEarlyData},
		// 44
		tls.ExtensionCookie: &tls.CookieExtension{},
		// 45
		tls.ExtensionPSKModes: &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		// 49
		tls.ExtensionPostHandShakeAuth: &tls.GenericExtension{Id: 49},
		// 57
		tls.ExtensionQUICTransportParameters: &tls.QUICTransportParametersExtension{},
		// 13172
		tls.ExtensionNextProtoNeg: &tls.NPNExtension{},
		// 65281
		tls.ExtensionRenegotiationInfo: &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
		//30032
		tls.ExtensionChannelId: &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}, //FIXME
	}
}

func getClientProfile(browserType string) ProfileData {
	// WINDOW_UPDATE
	// uc , 360, qq ,opera ,chrome,xiaomi ,samsung
	connectionFlow := uint32(15663105)
	//
	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	}
	// qq ,opera ,!360 ,!firefox ,chrome
	settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	}
	// signature_algorithms ,13
	// qq , opera , 360 , !firefox ,uc ,chrome ,xiaomi, samsung
	supportedSignatureAlgorithms := []string{
		"ECDSAWithP256AndSHA256", //1027
		"PSSWithSHA256",          //2052
		"PKCS1WithSHA256",        //1025
		"ECDSAWithP384AndSHA384", //1283
		"PSSWithSHA384",          //2053
		"PKCS1WithSHA384",        //1281
		"PSSWithSHA512",          //2054
		"PKCS1WithSHA512",        //1537
	}

	//delegated_credentials 34
	// !qq, !opera ,!360 !firefox ,只有firefox有 ,!chrome
	supportedDelegatedCredentialsAlgorithms := []string{}

	//supported_versions ,43
	// qq , opera , !firefox ,!360 , chrome ,samsung,edge
	supportedVersions := []string{"GREASE", "1.3", "1.2"}

	//key_share ,51
	// !qq , !opera ,!360 ,!firefox ,!chrome ,!safari
	keyShareCurves := []string{"GREASE", "X25519"}

	//protocol_name_list ,16
	// qq ,firefox ,360 ,opera ,uc ,chrome ,safari,xiaomi ,sansung
	supportedProtocolsALPN := []string{"h2", "http/1.1"}

	// supported_protocols ,17613
	// qq ,opera ,!firefox ,360 ,uc ,chrome ,!xiaomi,sansung
	supportedProtocolsALPS := []string{"h2"}

	// 65037 构建helloid
	// !uc ,!360
	candidatePayloads := []uint16{}
	// qq ,opera ,360 ,!firefox ,uc ,chrome ,xiaomi,sansung
	certCompressionAlgo := "brotli"
	// qq ,opera ,firefox ,360 ,uc ,chrome ,xiaomi,17个
	pseudoHeaderOrder := []string{
		":method",
		":authority",
		":scheme",
		":path",
	}
	echCandidateCipherSuites := []CandidateCipherSuites{}

	// for firefox
	priorities := []http2.Priority{}
	headerPriority := &http2.PriorityParam{}

	switch browserType {
	case Edge:
		settings = map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxHeaderListSize: 262144,
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
		pseudoHeaderOrder = []string{":method",
			":authority",
			":scheme",
			":path",
		}
		keyShareCurves = []string{"GREASE", "X25519MLKEM768", "X25519"}
		headerPriority = &http2.PriorityParam{
			StreamDep: 0,
			Exclusive: true,
			Weight:    0,
		}
		supportedProtocolsALPN = []string{"http/1.1", "h2"}

	case Samsung:
		settings = map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxHeaderListSize: 262144,
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
		keyShareCurves = []string{"GREASE", "X25519"}
		headerPriority = &http2.PriorityParam{
			StreamDep: 0,
			Exclusive: true,
			Weight:    0,
		}
		pseudoHeaderOrder = []string{":method",
			":authority",
			":scheme",
			":path",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"accept-language",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"accept-encoding",
			"priority",
		}

	case Xiaomi:
		settings = map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
		supportedProtocolsALPS = []string{}

		headerPriority = &http2.PriorityParam{
			Weight:    0,
			StreamDep: 0,
			Exclusive: true,
		}
		keyShareCurves = []string{"GREASE", "X25519"}
		supportedVersions = []string{"GREASE", "1.3", "1.2", "1.1", "1.0"}
		pseudoHeaderOrder = []string{
			":method", ":authority", ":scheme", ":path",
		}
	case Safari, IOS:
		certCompressionAlgo = "zlib"
		keyShareCurves = []string{"GREASE", "X25519"}
		supportedVersions = []string{"GREASE", "1.3", "1.2", "1.1", "1.0"}
		settings = map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingInitialWindowSize:    4194304,
			http2.SettingMaxConcurrentStreams: 100,
		}
		settingsOrder = []http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		}
		connectionFlow = uint32(10485760)
		pseudoHeaderOrder = []string{
			":method",
			":scheme",
			":path",
			":authority",
			"accept",
			"sec-fetch-site",
			"accept-encoding",
			"sec-fetch-mode",
			"user-agent",
			"accept-language",
			"sec-fetch-dest",
		}
		headerPriority = &http2.PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: false,
		}
		supportedSignatureAlgorithms = []string{
			"ECDSAWithP256AndSHA256",
			"PSSWithSHA256",
			"PKCS1WithSHA256",
			"ECDSAWithP384AndSHA384",
			"ECDSAWithSHA1",
			"PSSWithSHA384",
			"PSSWithSHA384",
			"PKCS1WithSHA384",
			"PSSWithSHA512",
			"PKCS1WithSHA512",
			"PKCS1WithSHA1",
		}
	case Chrome:
		//133
		candidatePayloads = []uint16{129, 32, 208}
		keyShareCurves = []string{"GREASE", "X25519MLKEM768", "X25519"} //2570 ,4588,29,
		pseudoHeaderOrder = []string{
			":method",
			":authority",
			":scheme",
			":path",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}

		echCandidateCipherSuites = []CandidateCipherSuites{
			{
				KdfId:  "HKDF_SHA256",
				AeadId: "AEAD_AES_128_GCM",
			},
		}
		headerPriority = &http2.PriorityParam{
			Weight:    0,
			StreamDep: 0,
			Exclusive: true,
		}
	case UC:
		keyShareCurves = []string{"GREASE", "X25519", "CurveP256", "CurveP384"} //2570 ,29,23,24
		supportedVersions = []string{"GREASE", "1.3", "1.2", "1.1", "1.0"}
		headerPriority = &http2.PriorityParam{
			Weight:    0,
			StreamDep: 0,
			Exclusive: true,
		}
		settings = map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
		pseudoHeaderOrder = []string{
			":method",
			":authority",
			":scheme",
			":path",
			"sec-fetch-dest",
			"user-agent",
			"accept",
			"x-ucbrowser-ua",
			"sec-fetch-site",
			"sec-fetch-mode",
			"accept-encoding",
			"accept-language",
		}

	case QH360:
		supportedVersions = []string{"GREASE", "1.3", "1.2", "1.1", "1.0"}
		headerPriority = &http2.PriorityParam{
			Weight:    0,
			StreamDep: 0,
			Exclusive: true,
		}
		settings = map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}

		pseudoHeaderOrder = []string{
			":method",
			":authority",
			":scheme",
			":path",
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
		}
	case Opera:
		candidatePayloads = []uint16{234, 32, 176}
		keyShareCurves = []string{"GREASE", "X25519MLKEM768", "X25519"}
		headerPriority = &http2.PriorityParam{
			Weight:    0,
			StreamDep: 0,
			Exclusive: true,
		}
		pseudoHeaderOrder = []string{
			":method",
			":authority",
			":scheme",
			":path",
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"priority",
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
	case QQ, QQMobile:
		candidatePayloads = []uint16{2, 32, 144}
		headerPriority = &http2.PriorityParam{
			Weight:    0,
			StreamDep: 0,
			Exclusive: true,
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
		keyShareCurves = []string{"GREASE", "X25519"}
		echCandidateCipherSuites = []CandidateCipherSuites{
			{
				KdfId:  "HKDF_SHA256",
				AeadId: "AEAD_AES_128_GCM",
			},
		}
		pseudoHeaderOrder = []string{
			":method",
			":authority",
			":scheme",
			":path",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
		}
	case Firefox:
		supportedProtocolsALPS = []string{}
		connectionFlow = uint32(12451840)
		candidatePayloads = []uint16{65, 32, 239}
		supportedSignatureAlgorithms = []string{
			"ECDSAWithP256AndSHA256",
			"ECDSAWithP384AndSHA384",
			"ECDSAWithP521AndSHA512",
			"PSSWithSHA256",
			"PSSWithSHA384",
			"PSSWithSHA512",
			"PKCS1WithSHA256",
			"PKCS1WithSHA384",
			"PKCS1WithSHA512",
			"ECDSAWithSHA1",
			"PKCS1WithSHA1",
		}
		supportedVersions = []string{"1.3", "1.2"}
		supportedDelegatedCredentialsAlgorithms = []string{
			"ECDSAWithP256AndSHA256",
			"ECDSAWithP384AndSHA384",
			"ECDSAWithP521AndSHA512",
			"ECDSAWithSHA1",
		}
		settings = map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxHeaderListSize: 16384,
		}
		settingsOrder = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
		keyShareCurves = []string{"CurveP256", "X25519"} //23 29 ,
		echCandidateCipherSuites = []CandidateCipherSuites{
			{
				KdfId:  "HKDF_SHA256",
				AeadId: "AEAD_AES_128_GCM",
			},
		}
		headerPriority = &http2.PriorityParam{
			Weight:    42,
			StreamDep: 13,
			Exclusive: false,
		}
		priorities = []http2.Priority{
			{
				StreamID: 3,
				PriorityParam: http2.PriorityParam{
					Exclusive: false,
					StreamDep: 0,
					Weight:    201,
				},
			},
			{
				StreamID: 5,
				PriorityParam: http2.PriorityParam{
					Exclusive: false,
					StreamDep: 0,
					Weight:    101,
				},
			},
			{
				StreamID: 7,
				PriorityParam: http2.PriorityParam{
					Exclusive: false,
					StreamDep: 0,
					Weight:    1,
				},
			},
			{
				StreamID: 9,
				PriorityParam: http2.PriorityParam{
					Exclusive: false,
					StreamDep: 7,
					Weight:    1,
				},
			},
			{
				StreamID: 11,
				PriorityParam: http2.PriorityParam{
					Exclusive: false,
					StreamDep: 3,
					Weight:    1,
				},
			},
			{
				StreamID: 13,
				PriorityParam: http2.PriorityParam{
					Exclusive: false,
					StreamDep: 0,
					Weight:    241,
				},
			},
		}
		pseudoHeaderOrder = []string{
			":method",
			":path",
			":authority",
			":scheme",
			"user-agent",
			"accept",
			"accept-language",
			"accept-encoding",
			"upgrade-insecure-requests",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"sec-fetch-user",
			"te",
		}
	default:
		candidatePayloads = []uint16{129, 32, 208}
		echCandidateCipherSuites = []CandidateCipherSuites{
			{
				KdfId:  "HKDF_SHA256",
				AeadId: "AEAD_AES_128_GCM",
			},
		}
		headerPriority = &http2.PriorityParam{
			Weight:    0,
			StreamDep: 0,
			Exclusive: true,
		}
	}

	return ProfileData{
		connectionFlow:                          connectionFlow,
		settingsOrder:                           settingsOrder,
		settings:                                settings,
		supportedSignatureAlgorithms:            supportedSignatureAlgorithms,
		supportedDelegatedCredentialsAlgorithms: supportedDelegatedCredentialsAlgorithms,
		supportedVersions:                       supportedVersions,
		keyShareCurves:                          keyShareCurves,
		supportedProtocolsALPN:                  supportedProtocolsALPN,
		supportedProtocolsALPS:                  supportedProtocolsALPS,
		candidatePayloads:                       candidatePayloads,
		pseudoHeaderOrder:                       pseudoHeaderOrder,
		priorities:                              priorities,
		headerPriority:                          headerPriority,
		certCompressionAlgo:                     certCompressionAlgo,
		echCandidateCipherSuites:                echCandidateCipherSuites,
	}

}
