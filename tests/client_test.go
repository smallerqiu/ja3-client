package tests

import (
	"testing"
)

func TestOne(t *testing.T) {
	// MatchTlsInfo(t, "qh360_16_0")
}
func TestChrome(t *testing.T) {
	t.Log("testing chrome 138")
	MatchTlsInfo(t, "chrome_138")

	t.Log("testing chrome 137")
	MatchTlsInfo(t, "chrome_137")

	t.Log("testing chrome_137_ios 137")
	MatchTlsInfo(t, "chrome_137_ios")

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

	t.Log("testing chrome_131_android")
	MatchTlsInfo(t, "chrome_131_android")

	t.Log("testing chrome_99_android")
	MatchTlsInfo(t, "chrome_99_android")

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

	t.Log("testing chrome 121")
	MatchTlsInfo(t, "chrome_121")

	t.Log("testing chrome 120")
	MatchTlsInfo(t, "chrome_120")

	t.Log("testing chrome 119")
	MatchTlsInfo(t, "chrome_119")

	t.Log("testing chrome 117")
	MatchTlsInfo(t, "chrome_117")

}

func TestOpera(t *testing.T) {
	t.Log("testing opera_120")
	MatchTlsInfo(t, "opera_120")

	t.Log("testing Opera 119")
	MatchTlsInfo(t, "opera_119")

	t.Log("testing Opera 117")
	MatchTlsInfo(t, "opera_117")
}

func TestEdge(t *testing.T) {
	t.Log("testing edge 138")
	MatchTlsInfo(t, "edge_138")

	t.Log("testing edge 137")
	MatchTlsInfo(t, "edge_137")

	t.Log("testing edge 136")
	MatchTlsInfo(t, "edge_136")

	t.Log("testing edge 135")
	MatchTlsInfo(t, "edge_135")

	t.Log("testing edge 134")
	MatchTlsInfo(t, "edge_134")

	t.Log("testing edge 133")
	MatchTlsInfo(t, "edge_133")

	t.Log("testing edge 132")
	MatchTlsInfo(t, "edge_132")

	t.Log("testing edge 131")
	MatchTlsInfo(t, "edge_131")

	t.Log("testing edge 101")
	MatchTlsInfo(t, "edge_101")
}

func TestFirefox(t *testing.T) {
	t.Log("testing firefox 140")
	MatchTlsInfo(t, "firefox_140")

	t.Log("testing firefox 139")
	MatchTlsInfo(t, "firefox_139")

	t.Log("testing firefox 138")
	MatchTlsInfo(t, "firefox_138")

	t.Log("testing firefox 137")
	MatchTlsInfo(t, "firefox_137")

	t.Log("testing firefox 136")
	MatchTlsInfo(t, "firefox_136")

	t.Log("testing firefox 135")
	MatchTlsInfo(t, "firefox_135")

	t.Log("testing firefox 134")
	MatchTlsInfo(t, "firefox_134")

	t.Log("testing firefox 133")
	MatchTlsInfo(t, "firefox_133")

	t.Log("testing firefox 132")
	MatchTlsInfo(t, "firefox_132")

	t.Log("testing firefox 123")
	MatchTlsInfo(t, "firefox_123")

	t.Log("testing firefox 120")
	MatchTlsInfo(t, "firefox_120")

	t.Log("testing firefox 117")
	MatchTlsInfo(t, "firefox_117")

}

func TestSafari(t *testing.T) {
	// mac
	t.Log("testing safari_26_0")
	MatchTlsInfo(t, "safari_26_0")

	t.Log("testing Safari_18_5")
	MatchTlsInfo(t, "safari_18_5")

	t.Log("testing Safari_18_1")
	MatchTlsInfo(t, "safari_18_1")

	t.Log("testing Safari_18_0")
	MatchTlsInfo(t, "safari_18_0")

	t.Log("testing Safari_17_0")
	MatchTlsInfo(t, "safari_17_0")

	t.Log("testing Safari_15_5")
	MatchTlsInfo(t, "safari_15_5")

	t.Log("testing Safari_15_3")
	MatchTlsInfo(t, "safari_15_3")

	//ios

	t.Log("testing safari_ios_26_0")
	MatchTlsInfo(t, "safari_ios_26_0")

	t.Log("testing Safari_IOS_18_5")
	MatchTlsInfo(t, "safari_ios_18_5")

	t.Log("testing Safari_IOS_18_0")
	MatchTlsInfo(t, "safari_ios_18_0")

	t.Log("testing Safari_IOS_17_0")
	MatchTlsInfo(t, "safari_ios_17_0")

}

func TestOthers(t *testing.T) {

	// t.Log("testing qq_19_4")
	// MatchTlsInfo(t, "qq_19_4")

	t.Log("testing uc_17_9")
	MatchTlsInfo(t, "uc_17_9")

	// t.Log("testing uc_110_9")// soon
	// // MatchTlsInfo(t, "uc_110_9")

	t.Log("testing qh360_16_0")
	MatchTlsInfo(t, "qh360_16_0")

	t.Log("testing xiaomi_15_9")
	MatchTlsInfo(t, "xiaomi_15_9")

	t.Log("testing samsung_27_1")
	MatchTlsInfo(t, "samsung_27_1")

	t.Log("testing tor_14_5")
	MatchTlsInfo(t, "tor_14_5")

	t.Log("testing brave_1_8")
	MatchTlsInfo(t, "brave_1_8")
}
