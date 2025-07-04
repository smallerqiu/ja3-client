package tests

import (
	"testing"
)

func TestChrome(t *testing.T) {

	t.Log("testing chrome 137")
	MatchTlsInfo(t, "chrome_137")

	t.Log("testing chrome 136")
	MatchTlsInfo(t, "chrome_136")

	t.Log("testing chrome 135")
	MatchTlsInfo(t, "chrome_135")

	t.Log("testing chrome 134")
	MatchTlsInfo(t, "chrome_134")
	return

	t.Log("testing chrome 133")
	MatchTlsInfo(t, "chrome_133")

	t.Log("testing chrome 132")
	MatchTlsInfo(t, "chrome_132")

	t.Log("testing chrome 131")
	MatchTlsInfo(t, "chrome_131")

	t.Log("testing chrome 130")
	MatchTlsInfo(t, "chrome_130")

	t.Log("testing chrome 129")
	MatchTlsInfo(t, "chrome_129")

	t.Log("testing chrome 128")
	MatchTlsInfo(t, "chrome_128")

	t.Log("testing chrome 127")
	MatchTlsInfo(t, "chrome_127")

	t.Log("testing chrome 126")
	MatchTlsInfo(t, "chrome_126")

	t.Log("testing chrome 125")
	MatchTlsInfo(t, "chrome_125")

	t.Log("testing chrome 124")
	MatchTlsInfo(t, "chrome_124")

	t.Log("testing chrome 123")
	MatchTlsInfo(t, "chrome_123")

	t.Log("testing chrome 122")
	MatchTlsInfo(t, "chrome_122")

	t.Log("testing chrome 120")
	MatchTlsInfo(t, "chrome_120")

	t.Log("testing chrome 119")
	MatchTlsInfo(t, "chrome_119")

	t.Log("testing chrome 117")
	MatchTlsInfo(t, "chrome_117")

	t.Log("testing chrome 116")
	MatchTlsInfo(t, "chrome_116_PSK")

	// Below 116 is too old.    It's meaningless.
}

func TestOpera(t *testing.T) {
	t.Log("testing Opera 119")
	MatchTlsInfo(t, "opera_119")

	t.Log("testing Opera 117")
	MatchTlsInfo(t, "opera_117")
}

func TestEdge(t *testing.T) {
	t.Log("testing edge 137")
	MatchTlsInfo(t, "edge_137")

	t.Log("testing edge 136")
	MatchTlsInfo(t, "edge_136")

	t.Log("testing edge 134")
	MatchTlsInfo(t, "edge_134")

	t.Log("testing edge 133")
	MatchTlsInfo(t, "edge_133")

	t.Log("testing edge 131")
	MatchTlsInfo(t, "edge_131")
}

func TestFirefox(t *testing.T) {
	t.Log("testing firefox 139")
	MatchTlsInfo(t, "firefox_139")

	t.Log("testing firefox 138")
	MatchTlsInfo(t, "firefox_138")
	return
	// t.Log("testing firefox 137")
	// MatchTlsInfo(t, "firefox_137")

	t.Log("testing firefox 136")
	MatchTlsInfo(t, "firefox_136")

	t.Log("testing firefox 135")
	MatchTlsInfo(t, "firefox_135")

	t.Log("testing firefox 133")
	MatchTlsInfo(t, "firefox_133")

	t.Log("testing firefox 132")
	MatchTlsInfo(t, "firefox_132")

	t.Log("testing firefox 129")
	MatchTlsInfo(t, "firefox_129")

	t.Log("testing firefox 124")
	MatchTlsInfo(t, "firefox_124")

	t.Log("testing firefox 123")
	MatchTlsInfo(t, "firefox_123")

	t.Log("testing firefox 120")
	MatchTlsInfo(t, "firefox_120")

	t.Log("testing firefox 117")
	MatchTlsInfo(t, "firefox_117")

}

func TestSafari(t *testing.T) {
	// mac
	t.Log("testing Safari_18_4")
	MatchTlsInfo(t, "safari_18_4")

	t.Log("testing Safari_18_1")
	MatchTlsInfo(t, "safari_18_1")

	t.Log("testing Safari_18_0")
	MatchTlsInfo(t, "safari_18_0")

	t.Log("testing Safari_17_5") // the same 17.0
	MatchTlsInfo(t, "safari_17_5")

	t.Log("testing Safari_16_0")
	MatchTlsInfo(t, "safari_16_0")

	t.Log("testing Safari_15_6_1") // the same 15_5
	MatchTlsInfo(t, "safari_15_6_1")

	t.Log("testing Safari_15_3")
	MatchTlsInfo(t, "safari_15_3")

	//ios

	t.Log("testing Safari_IOS_18_0")
	MatchTlsInfo(t, "safari_ios_18_0")

	t.Log("testing Safari_IOS_17_0")
	MatchTlsInfo(t, "safari_ios_17_0")

	t.Log("testing Safari_IOS_16_7")
	MatchTlsInfo(t, "safari_ios_16_7")

	t.Log("testing Safari_IOS_16_0")
	MatchTlsInfo(t, "safari_ios_16_0")

	t.Log("testing Safari_IOS_15_6")
	MatchTlsInfo(t, "safari_ios_15_6")

	t.Log("testing Safari_IOS_15_5")
	MatchTlsInfo(t, "safari_ios_15_5")

	//ipad
	t.Log("testing Safari_Ipad_15_6")
	MatchTlsInfo(t, "safari_ipad_15_6")
}

func TestChina(t *testing.T) {

	t.Log("testing qq 13_5")
	MatchTlsInfo(t, "qq_13_5")

	t.Log("testing uc_17_3")
	MatchTlsInfo(t, "uc_17_3")

	t.Log("testing 360_14_5")
	MatchTlsInfo(t, "360_14_5")

	t.Log("testing xiaomi_15_9")
	MatchTlsInfo(t, "xiaomi_15_9")

	t.Log("testing sansung_27_1")
	MatchTlsInfo(t, "sansung_27_1")

	t.Log("testing uc_17_3")
	MatchTlsInfo(t, "uc_17_3")

}
