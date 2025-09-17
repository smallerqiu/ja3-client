package ja3

var DefaultImpersonate = "chrome_139"

var DefaultClient = Chrome_139

var DefaultClientProfile, _ = BuildClientHelloSpec(DefaultImpersonate)

func c(current, target ClientData) ClientData {
	n := target
	n.UserAgent = current.UserAgent
	if current.WithHttp3 {
		n.WithHttp3 = current.WithHttp3
	}
	return n
}

var MappedTLSClients = map[string]ClientData{
	// "custom":          Custom,
	"chrome_139":         c(Chrome_139, Chrome_136),
	"chrome_138":         c(Chrome_138, Chrome_136),
	"chrome_137":         c(Chrome_137, Chrome_136),
	"chrome_137_ios":     Chrome_137_ios,
	"chrome_136":         Chrome_136,
	"chrome_135":         c(Chrome_135, Chrome_132),
	"chrome_134":         c(Chrome_134, Chrome_132),
	"chrome_133":         c(Chrome_133, Chrome_132),
	"chrome_132":         Chrome_132,
	"chrome_131_android": Chrome_131_android,
	"chrome_99_android":  Chrome_99_android,
	"chrome_131":         Chrome_131,
	"chrome_130":         c(Chrome_130, Chrome_124),
	"chrome_129":         c(Chrome_129, Chrome_124),
	"chrome_128":         c(Chrome_128, Chrome_124),
	"chrome_127":         c(Chrome_127, Chrome_124),
	"chrome_126":         c(Chrome_126, Chrome_124),
	"chrome_125":         c(Chrome_125, Chrome_124),
	"chrome_124":         Chrome_124,
	"chrome_123":         c(Chrome_123, Chrome_119),
	"chrome_122":         c(Chrome_122, Chrome_119),
	"chrome_121":         c(Chrome_121, Chrome_119),
	"chrome_120":         c(Chrome_120, Chrome_119),
	"chrome_119":         Chrome_119,
	"chrome_117":         Chrome_117,
	"edge_139":           c(Edge_139, Edge_136),
	"edge_138":           c(Edge_138, Edge_136),
	"edge_137":           c(Edge_137, Edge_136),
	"edge_136":           Edge_136,
	"edge_135":           c(Edge_135, Edge_131),
	"edge_134":           c(Edge_134, Edge_131),
	"edge_133":           c(Edge_133, Edge_131),
	"edge_132":           c(Edge_132, Edge_131),
	"edge_131":           Edge_131,
	"edge_101":           Edge_101,
	"firefox_142":        c(Firefox_142, Firefox_135),
	"firefox_141":        c(Firefox_141, Firefox_135),
	"firefox_140":        c(Firefox_140, Firefox_135),
	"firefox_139":        c(Firefox_139, Firefox_135),
	"firefox_138":        c(Firefox_138, Firefox_135),
	"firefox_137":        c(Firefox_137, Firefox_135),
	"firefox_136":        c(Firefox_136, Firefox_135),
	"firefox_135":        Firefox_135,
	"firefox_134":        c(Firefox_134, Firefox_132),
	"firefox_133":        c(Firefox_133, Firefox_132),
	"firefox_132":        Firefox_132,
	"firefox_123":        Firefox_123,
	"firefox_120":        Firefox_120,
	"firefox_117":        Firefox_117,
	"opera_120":          Opera_120,
	"opera_119":          c(Opera_119, Opera_117),
	"opera_117":          Opera_117,
	"safari_15_3":        Safari_15_3,
	"safari_15_5":        Safari_15_5,
	"safari_17_0":        Safari_17_0,
	"safari_18_0":        Safari_18_0,
	"safari_18_1":        Safari_18_1,
	"safari_18_5":        Safari_18_5,
	"safari_26_0":        Safari_26_0,
	"safari_ios_17_0":    Safari_ios_17_0,
	"safari_ios_18_0":    Safari_ios_18_0,
	"safari_ios_18_5":    Safari_ios_18_5,
	"safari_ios_26_0":    Safari_ios_26_0,
	"tor_14_5":           Tor_14_5,
	"brave_1_8":          Brave_1_8,
	// "qq_19_4":            QQ_19_4, // soon
	"qh360_16_0":    QH360_16_0,
	"qh360_5_5_ios": QH360_5_5_ios,
	"uc_17_9":       UC_17_9,
	// "uc_110_9":           UC_110_9, // discarded
	"samsung_27_1": Samsung_27_1,
	"xiaomi_15_9":  Xiaomi_15_9,
}
