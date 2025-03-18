package tests

import (
	"testing"
)

func TestClient(t *testing.T) {
	t.Log("testing safari_ios_16_7")
	MatchTlsInfo(t, "safari_ios_16_7")

	t.Log("testing safari_18_1")
	MatchTlsInfo(t, "safari_18_1")

	t.Log("testing edge_133")
	MatchTlsInfo(t, "edge_133")

	t.Log("testing opera_117")
	MatchTlsInfo(t, "opera_117")

	t.Log("testing firefox_135")
	MatchTlsInfo(t, "firefox_135")

	t.Log("testing firefox_136")
	MatchTlsInfo(t, "firefox_136")

	// // for China

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
