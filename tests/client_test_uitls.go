package tests

import (
	"encoding/json"
	"io"
	"log"
	"testing"

	tls "github.com/smallerqiu/ja3-client"
	"github.com/smallerqiu/ja3-client/http"
)

// 不稳定
var tlsApi = "https://tls.browserleaks.com/json"

type TlsInfo struct {
	Ja3Hash    string `json:"ja3_hash"`
	Ja3Text    string `json:"ja3_text"`
	Ja3nHash   string `json:"ja3n_hash"`
	Ja3nText   string `json:"ja3n_text"`
	Ja4        string `json:"ja4"`
	AkamaiHash string `json:"akamai_hash"`
	AkamaiText string `json:"akamai_text"`
}

// var peetApi = "https://tls.peet.ws/api/all"

type PeetInfo struct {
	TLS struct {
		Ja3     string `json:"ja3"`
		Ja3Hash string `json:"ja3n_hash"`
		Ja4     string `json:"ja4"`
	} `json:"tls"`
	Http2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
	} `json:"http2"`
}

var TlsInfoMap = map[string]map[string]string{
	"chrome_134": {
		"ja3_hash":    "4b75d8be9006dc44ad4186a017a97466",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-65281-5-35-51-43-11-65037-17613-45-27-16-23-0-10-13,4588-29-23-24,0",
		"ja3n_hash":   "8e19337e7524d2573be54efb2b0784c9",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,4588-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_133": {
		"ja3_hash":    "cc92645aa065cc727504d473c5a4e153",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-0-16-18-43-45-5-17613-10-65281-23-11-65037-13-27-35,4588-29-23-24,0",
		"ja3n_hash":   "8e19337e7524d2573be54efb2b0784c9",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,4588-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_132": {
		"ja3_hash":    "ae8cb9f125f770d1a577f5a55b0d9942",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-17613-65281-35-11-10-45-18-65037-0-23-51-27-16-43-5,4588-29-23-24,0",
		"ja3n_hash":   "8e19337e7524d2573be54efb2b0784c9",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,4588-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_131": {
		"ja3_hash":    "4c332c2869aefe1fe0b809eab82ef134",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-16-65037-17513-13-27-51-18-45-23-0-65281-11-10-5-43,4588-29-23-24,0",
		"ja3n_hash":   "dee19b855b658c6aa0f575eda2525e19",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,4588-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_130": {
		"ja3_hash":    "260601dddd43c9315bb86f9209ef8469",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17513-11-65037-27-5-35-45-16-65281-0-51-10-13-23-18-43,25497-29-23-24,0",
		"ja3n_hash":   "4c9ce26028c11d7544da00d3f7e4f45c",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_129": {
		"ja3_hash":    "d8a0b183dc36fc67184804f1dfb2ae64",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65037-18-27-45-11-17513-23-51-10-35-13-16-5-65281-0-43,25497-29-23-24,0",
		"ja3n_hash":   "4c9ce26028c11d7544da00d3f7e4f45c",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_128": {
		"ja3_hash":    "05fd5e7b3f1a305eeb3b5ee597e5ad3e",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-0-10-35-23-17513-11-5-51-43-65281-45-16-27-13-65037,25497-29-23-24,0",
		"ja3n_hash":   "4c9ce26028c11d7544da00d3f7e4f45c",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_127": {
		"ja3_hash":    "bbf903e7faed1092eed22a1f3aa09d18",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-0-23-51-27-45-65281-16-35-10-17513-11-13-43-65037-18,25497-29-23-24,0",
		"ja3n_hash":   "4c9ce26028c11d7544da00d3f7e4f45c",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_126": {
		"ja3_hash":    "198462c82bb00e4d93d6496b59dc9892",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,16-65281-18-17513-51-0-35-5-27-10-43-65037-13-45-11-23,25497-29-23-24,0",
		"ja3n_hash":   "4c9ce26028c11d7544da00d3f7e4f45c",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_125": {
		"ja3_hash":    "78ca57792a2c501849ab315e54592e97",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,27-65281-17513-0-18-45-13-65037-51-11-5-35-43-10-16-23,25497-29-23-24,0",
		"ja3n_hash":   "4c9ce26028c11d7544da00d3f7e4f45c",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_124": {
		"ja3_hash":    "33b7ce0188c6920423676b3b2e0cbe41",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-51-43-11-23-65037-45-16-18-13-17513-65281-27-10-0-5,25497-29-23-24,0",
		"ja3n_hash":   "4c9ce26028c11d7544da00d3f7e4f45c",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_122": {
		"ja3_hash":    "6d4d2c5467cac8b1104e5279196f7667",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-16-10-23-27-65037-0-17513-51-43-5-18-45-11-35-13,29-23-24,0",
		"ja3n_hash":   "473f0e7c0b6a0f7b049072f4e683068b",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_120": {
		"ja3_hash":    "46d38580d53d0f21ffa4657314f12f21",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-43-35-13-65281-51-10-18-27-45-17513-65037-23-16-0-11,29-23-24,0",
		"ja3n_hash":   "473f0e7c0b6a0f7b049072f4e683068b",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_119": {
		"ja3_hash":    "dec389cd87b6228b628f6761a28221fa",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65037-17513-23-35-65281-51-45-13-27-18-43-10-5-11-0-16,29-23-24,0",
		"ja3n_hash":   "473f0e7c0b6a0f7b049072f4e683068b",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_117": {
		"ja3_hash":    "1ddf8a0ebd957d10c1ab320b10450028",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-0-16-13-43-17513-10-23-35-27-18-5-51-65281-11-21,29-23-24,0",
		"ja3n_hash":   "aa56c057ad164ec4fdcb7a5a283be9fc",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65281,29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_e5627efa2ab1",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"chrome_116_PSK": {
		"ja3_hash":    "9e58556f03f8549b9cfac49bdfff3f97",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-17513-43-13-51-10-5-35-16-45-65281-23-0-27-18-21,29-23-24,0",
		"ja3n_hash":   "aa56c057ad164ec4fdcb7a5a283be9fc",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65281,29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_e5627efa2ab1",
		"akamai_hash": "a345a694846ad9f6c97bcc3c75adbe26",
	},
	"safari_18_1": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "959a7e813b79b909a1a0b00a38e8bba3",
	},
	"safari_18_0": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_e42f34c56612",
		"akamai_hash": "d4a2dcbfde511b5040ed5a5190a8d78b",
	},
	"safari_17_5": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "959a7e813b79b909a1a0b00a38e8bba3",
	},
	"safari_16_0": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "dda308d35f4e5db7b52a61720ca1b122",
	},
	"safari_15_6_1": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "dda308d35f4e5db7b52a61720ca1b122",
	},
	"safari_15_3": {
		"ja3_hash":    "656b9a2f4de6ed4909e157482860ab3d",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-21,29-23-24-25,0",
		"ja3n_hash":   "4e732e0294d23442159b756947e9daba",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2613h2_2802a3db6c62_845d286b0d67",
		"akamai_hash": "dda308d35f4e5db7b52a61720ca1b122",
	},
	"safari_ios_18_0": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_e42f34c56612",
		"akamai_hash": "d4a2dcbfde511b5040ed5a5190a8d78b",
	},
	"safari_ios_17_0": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "ad8424af1cc590e09f7b0c499bf7fcdb",
	},
	"safari_ios_16_7": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "d5fcbdc393757341115a861bf8d23265",
	},
	"safari_ios_16_0": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "d5fcbdc393757341115a861bf8d23265",
	},
	"safari_ios_15_6": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "d5fcbdc393757341115a861bf8d23265",
	},
	"safari_ios_15_5": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "d5fcbdc393757341115a861bf8d23265",
	},
	"safari_ipad_15_6": {
		"ja3_hash":    "773906b0efdefa24a7f2b8eb6985bf37",
		"ja3_text":    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		"ja3n_hash":   "44f7ed5185d22c92b96da72dbe68d307",
		"ja3n_text":   "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
		"ja4":         "t13d2014h2_a09f3c656075_14788d8d241b",
		"akamai_hash": "d5fcbdc393757341115a861bf8d23265",
	},
	"firefox_136": {
		"ja3_hash":    "6f7889b9fb1a62a9577e685c1fcfa919",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
		"ja3n_hash":   "e4147a4860c1f347354f0a84d8787c02",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-65037-65281,4588-29-23-24-25-256-257,0",
		"ja4":         "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
		"akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	},
	"firefox_135": {
		"ja3_hash":    "6f7889b9fb1a62a9577e685c1fcfa919",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
		"ja3n_hash":   "e4147a4860c1f347354f0a84d8787c02",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-65037-65281,4588-29-23-24-25-256-257,0",
		"ja4":         "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
		"akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	},
	"firefox_133": {
		"ja3_hash":    "a767f8ae9115cc5752e5cff59612e74f",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-27-65037,4588-29-23-24-25-256-257,0",
		"ja3n_hash":   "bef19372d2dde1691261e80e94bca446",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-23-27-28-34-43-51-65037-65281,4588-29-23-24-25-256-257,0",
		"ja4":         "t13d1714h2_5b57614c22b0_3dd24b5ebec4",
		"akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	},
	"firefox_132": {
		"ja3_hash":    "a767f8ae9115cc5752e5cff59612e74f",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-27-65037,4588-29-23-24-25-256-257,0",
		"ja3n_hash":   "bef19372d2dde1691261e80e94bca446",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-23-27-28-34-43-51-65037-65281,4588-29-23-24-25-256-257,0",
		"ja4":         "t13d1714h2_5b57614c22b0_3dd24b5ebec4",
		"akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	},
	"firefox_129": {
		"ja3_hash":    "b5001237acdf006056b409cc433726b0",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
		"ja3n_hash":   "6de49d1869679eda9dccc6c9057cfd94",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-23-28-34-35-43-45-51-65037-65281,29-23-24-25-256-257,0",
		"ja4":         "t13d1715h2_5b57614c22b0_5c2c66f702b0",
		"akamai_hash": "3d9132023bf26a71d40fe766e5c24c9d",
	},
	"firefox_124": {
		"ja3_hash":    "4ab323b654a363c2dd3101ab5d3db443",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,16-28-35-43-10-65037-5-13-45-65281-34-0-23-51-11,29-23-24-25-256-257,0",
		"ja3n_hash":   "6de49d1869679eda9dccc6c9057cfd94",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-23-28-34-35-43-45-51-65037-65281,29-23-24-25-256-257,0",
		"ja4":         "t13d1715h2_5b57614c22b0_5c2c66f702b0",
		"akamai_hash": "f074f027d9d6d451fab975ea1e0d2712",
	},
	"firefox_123": {
		"ja3_hash":    "b5001237acdf006056b409cc433726b0",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
		"ja3n_hash":   "6de49d1869679eda9dccc6c9057cfd94",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-23-28-34-35-43-45-51-65037-65281,29-23-24-25-256-257,0",
		"ja4":         "t13d1715h2_5b57614c22b0_5c2c66f702b0",
		"akamai_hash": "3d9132023bf26a71d40fe766e5c24c9d",
	},
	"firefox_120": {
		"ja3_hash":    "ed3d2cb3d86125377f5a4d48e431af48",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-65037,29-23-24-25-256-257,0",
		"ja3n_hash":   "236c269e47883ea5a822854682ba5127",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-23-28-34-43-51-65037-65281,29-23-24-25-256-257,0",
		"ja4":         "t13d1713h2_5b57614c22b0_748f4c70de1c",
		"akamai_hash": "3d9132023bf26a71d40fe766e5c24c9d",
	},
	"firefox_117": {
		"ja3_hash":    "579ccef312d18482fc42e2b822ca2430",
		"ja3_text":    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
		"ja3n_hash":   "b1efda11c805621e0f9cdc311958cb8c",
		"ja3n_text":   "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-21-23-28-34-35-43-45-51-65281,29-23-24-25-256-257,0",
		"ja4":         "t13d1715h2_5b57614c22b0_3d5424432f57",
		"akamai_hash": "3d9132023bf26a71d40fe766e5c24c9d",
	},
	"edge_134": {
		"ja3_hash":    "34a72235a04cecc90d8847964db0a29d",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65037-43-11-16-27-13-10-18-5-51-35-17513-65281-0-23-45,4588-29-23-24,0",
		"ja3n_hash":   "dee19b855b658c6aa0f575eda2525e19",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,4588-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"edge_133": {
		"ja3_hash":    "d5984a9f5d4bc7662863b15f764c26d5",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-11-18-35-17513-27-16-65281-43-65037-13-10-45-51-5-0,4588-29-23-24,0",
		"ja3n_hash":   "dee19b855b658c6aa0f575eda2525e19",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,4588-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"edge_131": {
		"ja3_hash":    "5389aa3f08ac30bcd2c1bfeb7ddda33c",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-11-65037-18-51-65281-13-43-17513-16-27-45-5-23-10-0,4588-29-23-24,0",
		"ja3n_hash":   "dee19b855b658c6aa0f575eda2525e19",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,4588-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"xiaomi_15_9": {
		"ja3_hash":    "b32309a26951912be7dba376398abc3b",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		"ja3n_hash":   "821cb817a47514f1db4ece75531b7610",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-21-23-27-35-43-45-51-65281,29-23-24,0",
		"ja4":         "t13d1515h2_8daaf6152771_de4a06bb82e3",
		"akamai_hash": "4f04edce68a7ecbe689edce7bf5f23f3",
	},
	"opera_117": {
		"ja3_hash":    "b425c31cf7fd7ad93d774ad4c357345c",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,43-0-10-18-5-11-23-35-45-17513-13-51-65281-65037-16-27,4588-29-23-24,0",
		"ja3n_hash":   "dee19b855b658c6aa0f575eda2525e19",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,4588-29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"qq_13_5": {
		"ja3_hash":    "9d933208a75cb79baf8dc1486514845f",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-43-65281-0-35-65037-13-27-17513-16-45-5-23-18-51-11-21,29-23-24,0",
		"ja3n_hash":   "8a9ee1d3c6f0f892b4d43cabcf554150",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65037-65281,29-23-24,0",
		"ja4":         "t13d1517h2_8daaf6152771_b1ff8ab2d16f",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"sansung_27_1": {
		"ja3_hash":    "4178197a33343e7d03c2c672adaa9440",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-27-16-43-17513-18-51-23-13-5-65037-35-10-65281-45-0,29-23-24,0",
		"ja3n_hash":   "473f0e7c0b6a0f7b049072f4e683068b",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0",
		"ja4":         "t13d1516h2_8daaf6152771_02713d6af862",
		"akamai_hash": "52d84b11737d980aef856699f885ca86",
	},
	"uc_17_3": {
		"ja3_hash":    "59344d8667ab05f835008b36153e5c0e",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-51-18-16-5-0-23-43-10-27-35-13-17513-65281-11-21,29-23-24,0",
		"ja3n_hash":   "aa56c057ad164ec4fdcb7a5a283be9fc",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65281,29-23-24,0",
		"ja4":         "t13d1516h1_8daaf6152771_e5627efa2ab1",
		"akamai_hash": "4f04edce68a7ecbe689edce7bf5f23f3",
	},
	"360_14_5": {
		"ja3_hash":    "1f7af0a0ec8e4701d045b413d0016902",
		"ja3_text":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-57363-57427-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
		"ja3n_hash":   "0b5baee6beca201985a665a399c4e1ad",
		"ja3n_text":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-57363-57427-156-157-47-53,0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65281,29-23-24,0",
		"ja4":         "t13d1716h2_e08a0f08260f_e5627efa2ab1",
		"akamai_hash": "a345a694846ad9f6c97bcc3c75adbe26",
	},
}

func getTlsInfo(t *testing.T, impersonate string) (tlsinfo TlsInfo) {
	reqBody := &tls.Ja3Request{
		Method: "GET",
		URL:    tlsApi,
		// Proxy:                "http://127.0.0.1:7890",
		Headers:              make(map[string][]string),
		Impersonate:          impersonate,
		RandomExtensionOrder: true,
	}
	// 创建 TLS 会话
	var client, request, err = tls.CreateSession(reqBody)

	if err != nil {
		log.Printf("Client Error: %v", err)
	}

	request.Header = http.Header{
		"accept":          {"*/*"},
		"accept-encoding": {"gzip"},
		"accept-language": {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		"user-agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) chrome/100.0.4896.75 safari/537.36"},
		http.HeaderOrderKey: {
			"accept",
			"accept-encoding",
			"accept-language",
			"user-agent",
		},
	}

	response, err := client.Do(request)
	defer client.CloseIdleConnections()

	if err != nil {
		log.Printf("Error response: %v", err)
	}

	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)

	if err != nil {
		log.Printf("Error response: %v", err)
	}

	// log.Printf("Response: %s", string(bytes))

	// log.Printf("%v,%s: %s", response.StatusCode, reqBody.Method, reqBody.URL)
	tlsinfo = TlsInfo{}
	if err := json.Unmarshal(bytes, &tlsinfo); err != nil {
		t.Fatal(err)
	}

	return tlsinfo
}

func MatchTlsInfo(t *testing.T, impersonate string) {

	tlsinfo := getTlsInfo(t, impersonate)

	info := TlsInfoMap[impersonate]

	// just match the ja3n_hash , ja4 , akamai_hash

	if tlsinfo.Ja3nHash != info["ja3n_hash"] {
		t.Logf("ja31: %v", tlsinfo.Ja3Text)
		t.Logf("ja32: %v", info["ja3n_text"])
		t.Errorf("ja3n hash mismatch: %s != %s", tlsinfo.Ja3nHash, info["ja3n_hash"])
	}
	if tlsinfo.Ja4 != info["ja4"] {
		t.Errorf("ja4 mismatch: %s != %s", tlsinfo.Ja4, info["ja4"])
	}
	if tlsinfo.AkamaiHash != info["akamai_hash"] {
		t.Logf("akamai_text: %v", tlsinfo.AkamaiText)
		t.Errorf("akamai hash mismatch: %s != %s", tlsinfo.AkamaiHash, info["akamai_hash"])
	}
}
