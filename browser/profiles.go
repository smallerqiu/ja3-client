package browser

import (
	"github.com/smallerqiu/ja3-client/http2"
	tls "github.com/smallerqiu/utls"
)

var DefaultClientProfile = Chrome_136

var MappedTLSClients = map[string]ClientProfile{
	"custom":                 Custom,
	"qq_13_5":                QQ_13_5,
	"uc_17_3":                UC_17_3,
	"360_14_5":               QH360_14_5,
	"xiaomi_15_9":            Xiaomi_15_9,
	"sansung_27_1":           Sansung_27_1,
	"chrome_103":             Chrome_103,
	"chrome_104":             Chrome_104,
	"chrome_105":             Chrome_105,
	"chrome_106":             Chrome_106,
	"chrome_107":             Chrome_107,
	"chrome_108":             Chrome_108,
	"chrome_109":             Chrome_109,
	"chrome_110":             Chrome_110,
	"chrome_111":             Chrome_111,
	"chrome_112":             Chrome_112,
	"chrome_116_PSK":         Chrome_116_PSK,
	"chrome_116_PSK_PQ":      Chrome_116_PSK_PQ,
	"chrome_117":             Chrome_117,
	"chrome_119":             Chrome_119,
	"chrome_120":             Chrome_120,
	"chrome_122":             Chrome_120,
	"chrome_123":             Chrome_120,
	"chrome_124":             Chrome_124,
	"chrome_125":             Chrome_125,
	"chrome_126":             Chrome_126,
	"chrome_127":             Chrome_126,
	"chrome_128":             Chrome_126,
	"chrome_129":             Chrome_126,
	"chrome_130":             Chrome_130,
	"chrome_131":             Chrome_131,
	"chrome_131_PSK":         Chrome_131_PSK,
	"chrome_133":             Chrome_133,
	"chrome_132":             Chrome_133,
	"chrome_133_PSK":         Chrome_133_PSK,
	"chrome_134":             Chrome_134,
	"chrome_135":             Chrome_135,
	"chrome_136":             Chrome_136,
	"chrome_137":             Chrome_136,
	"safari_15_3":            Safari_15_3,
	"safari_15_6_1":          Safari_15_6_1,
	"safari_16_0":            Safari_16_0,
	"safari_17_0":            Safari_17_5,
	"safari_17_5":            Safari_17_5,
	"safari_18_0":            Safari_18_0,
	"safari_18_1":            Safari_18_1,
	"safari_18_4":            Safari_18_4,
	"safari_18_5":            Safari_18_4,
	"safari_ipad_15_6":       Safari_Ipad_15_6,
	"safari_ios_15_5":        Safari_IOS_15_5,
	"safari_ios_15_6":        Safari_IOS_15_6,
	"safari_ios_16_0":        Safari_IOS_16_0,
	"safari_ios_16_7":        Safari_IOS_16_7,
	"safari_ios_17_0":        Safari_IOS_17_0,
	"safari_ios_18_0":        Safari_IOS_18_0,
	"firefox_102":            Firefox_102,
	"firefox_104":            Firefox_104, // not supported , test unreliable
	"firefox_105":            Firefox_105,
	"firefox_106":            Firefox_106,
	"firefox_108":            Firefox_108,
	"firefox_110":            Firefox_110,
	"firefox_117":            Firefox_117,
	"firefox_120":            Firefox_120,
	"firefox_123":            Firefox_123,
	"firefox_124":            Firefox_124,
	"firefox_129":            Firefox_129,
	"firefox_132":            Firefox_132,
	"firefox_133":            Firefox_133,
	"firefox_135":            Firefox_135,
	"firefox_136":            Firefox_136,
	"firefox_137":            Firefox_136,
	"firefox_138":            Firefox_136,
	"firefox_139":            Firefox_136,
	"opera_89":               Opera_89,
	"opera_90":               Opera_90,
	"opera_91":               Opera_91,
	"opera_117":              Opera_117,
	"opera_119":              Opera_119,
	"edge_131":               Edge_131,
	"edge_133":               Edge_133,
	"edge_134":               Edge_134,
	"edge_136":               Edge_136,
	"edge_137":               Edge_136,
	"zalando_android_mobile": ZalandoAndroidMobile,
	"zalando_ios_mobile":     ZalandoIosMobile,
	"nike_ios_mobile":        NikeIosMobile,
	"nike_android_mobile":    NikeAndroidMobile,
	"cloudscraper":           CloudflareCustom,
	"mms_ios":                MMSIos,
	"mms_ios_1":              MMSIos,
	"mms_ios_2":              MMSIos2,
	"mms_ios_3":              MMSIos3,
	"mesh_ios":               MeshIos,
	"mesh_ios_1":             MeshIos,
	"mesh_ios_2":             MeshIos2,
	"mesh_android":           MeshAndroid,
	"mesh_android_1":         MeshAndroid,
	"mesh_android_2":         MeshAndroid2,
	"confirmed_ios":          ConfirmedIos,
	"confirmed_android":      ConfirmedAndroid,
	"okhttp4_android_7":      Okhttp4Android7,
	"okhttp4_android_8":      Okhttp4Android8,
	"okhttp4_android_9":      Okhttp4Android9,
	"okhttp4_android_10":     Okhttp4Android10,
	"okhttp4_android_11":     Okhttp4Android11,
	"okhttp4_android_12":     Okhttp4Android12,
	"okhttp4_android_13":     Okhttp4Android13,
}

type ClientProfile struct {
	clientHelloId     tls.ClientHelloID
	headerPriority    *http2.PriorityParam
	settings          map[http2.SettingID]uint32
	priorities        []http2.Priority
	pseudoHeaderOrder []string
	settingsOrder     []http2.SettingID
	connectionFlow    uint32
}

func NewClientProfile(clientHelloId tls.ClientHelloID, settings map[http2.SettingID]uint32, settingsOrder []http2.SettingID, pseudoHeaderOrder []string, connectionFlow uint32, priorities []http2.Priority, headerPriority *http2.PriorityParam) ClientProfile {
	return ClientProfile{
		clientHelloId:     clientHelloId,
		settings:          settings,
		settingsOrder:     settingsOrder,
		pseudoHeaderOrder: pseudoHeaderOrder,
		connectionFlow:    connectionFlow,
		priorities:        priorities,
		headerPriority:    headerPriority,
	}
}
func (c ClientProfile) GetClientHelloSpec() (tls.ClientHelloSpec, error) {
	return c.clientHelloId.ToSpec()
}

func (c ClientProfile) GetClientHelloStr() string {
	return c.clientHelloId.Str()
}

func (c ClientProfile) GetSettings() map[http2.SettingID]uint32 {
	return c.settings
}

func (c ClientProfile) GetSettingsOrder() []http2.SettingID {
	return c.settingsOrder
}

func (c ClientProfile) GetConnectionFlow() uint32 {
	return c.connectionFlow
}

func (c ClientProfile) GetPseudoHeaderOrder() []string {
	return c.pseudoHeaderOrder
}

func (c ClientProfile) GetHeaderPriority() *http2.PriorityParam {
	return c.headerPriority
}

func (c ClientProfile) GetClientHelloId() tls.ClientHelloID {
	return c.clientHelloId
}

func (c ClientProfile) GetPriorities() []http2.Priority {
	return c.priorities
}
