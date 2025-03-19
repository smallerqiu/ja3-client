package tests

import (
	"testing"
)

func TestChrome(t *testing.T) {
	t.Log("testing chrome 134")
	MatchTlsInfo(t, "chrome_134")

	t.Log("testing chrome 133")
	MatchTlsInfo(t, "chrome_133")

	t.Log("testing chrome 131")
	MatchTlsInfo(t, "chrome_131")

	t.Log("testing chrome 124")
	MatchTlsInfo(t, "chrome_124")

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

func TestEdge(t *testing.T) {
	t.Log("testing edge 134")
	MatchTlsInfo(t, "edge_134")

	t.Log("testing edge 133")
	MatchTlsInfo(t, "edge_133")

	t.Log("testing edge 131")
	MatchTlsInfo(t, "edge_131")
}

func TestFirefox(t *testing.T) {
	t.Log("testing firefox 135")
	MatchTlsInfo(t, "firefox 135")
}

func TestSafari(t *testing.T) {
	t.Log("testing safari_ios_16_7")
	MatchTlsInfo(t, "safari_ios_16_7")

	t.Log("testing safari_18_1")
	MatchTlsInfo(t, "safari_18_1")

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
