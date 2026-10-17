package ja3

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"

	tls "github.com/smallerqiu/utls"
)

// The captures under client_data/ and data_peet/ (gitignored: they are someone's
// machine fingerprint) agree on one ja4 per Chrome band. Those hashes are pinned
// here so a profile edit that silently changes the extension set, the cipher list or
// the signature_algorithms order fails a test instead of shipping.
//
// Measured 2026-10-15/17 against tls.peet.ws and tls.browserleaks.com, HTTP/2 (so
// the ALPN tag is h2 and no h3 is offered).
var goldenJA4 = map[string]string{
	// Chrome 136 through 149: sixteen extensions, signature_algorithms opening on
	// ecdsa_secp256r1_sha256. chrome_132 and chrome_141 land in the same band.
	"chrome_132": "8daaf6152771_d8a2da3f94cd",
	"chrome_136": "8daaf6152771_d8a2da3f94cd",
	"chrome_141": "8daaf6152771_d8a2da3f94cd",
	"chrome_142": "8daaf6152771_d8a2da3f94cd",
	"chrome_143": "8daaf6152771_d8a2da3f94cd",
	"chrome_149": "8daaf6152771_d8a2da3f94cd",
	// Chrome 150 and 151: the same sixteen extensions, but signature_algorithms now
	// opens on the ML-DSA schemes (0904, 0905, 0906).
	"chrome_150": "8daaf6152771_806a8c22fdea",
	"chrome_151": "8daaf6152771_806a8c22fdea",
	// Chrome 152 and up: trust_anchors (51764) joins the set, seventeen extensions.
	"chrome_152": "8daaf6152771_cb7bf5808d99",
	"chrome_155": "8daaf6152771_cb7bf5808d99",
}

func isGreaseCode(i uint16) bool { return i&0xff == i>>8 && i&0x0f == 0x0a }

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ja4Of computes the two hashed halves of the ja4 peet reports, straight from the
// built spec:
//
//	sha256(sorted cipher ids, GREASE dropped)[:12] _
//	sha256(sorted extension ids without SNI and ALPN, GREASE dropped, joined with
//	       "," + "_" + signature_algorithms in the order they go out)[:12]
//
// The extension count and the ALPN tag are left out: they are format noise, and the
// count is asserted separately.
//
// Three offline quirks the walk works around: SNIExtension reports Len() == 0 until a
// server name exists, so its id is added back by hand; the padding extension only
// learns its length from the unpadded hello, measured on a first pass that skips it;
// and forcePad overrides that decision, because a built hello is a few dozen bytes
// shorter than a real Chrome's and would land inside or outside BoringSSL's padding
// window at random.
func ja4Of(t *testing.T, profile ClientProfile, forcePad bool) (body string, extCount int) {
	t.Helper()
	spec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("GetClientHelloSpec: %v", err)
	}
	var ciphers []string
	for _, c := range spec.CipherSuites {
		if !isGreaseCode(c) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", c))
		}
	}
	sort.Strings(ciphers)

	walk := func(unpadded int) (ids []uint16, sigs []uint16, size int) {
		for _, ext := range spec.Extensions {
			if _, ok := ext.(*tls.UtlsGREASEExtension); ok {
				continue
			}
			if p, ok := ext.(*tls.UtlsPaddingExtension); ok {
				if unpadded == 0 {
					continue
				}
				if forcePad {
					p.WillPad, p.PaddingLen = true, 10
				} else {
					p.Update(unpadded)
				}
			}
			n := ext.Len()
			if n == 0 {
				continue
			}
			buf := make([]byte, n)
			read, _ := ext.Read(buf) // utls returns the full length along with io.EOF
			if read < 4 {
				continue
			}
			id := binary.BigEndian.Uint16(buf[:2])
			if isGreaseCode(id) {
				continue
			}
			size += n
			ids = append(ids, id)
			if id != 13 {
				continue
			}
			body := buf[4:read]
			if len(body) < 2 {
				continue
			}
			list := body[2:]
			if l := int(binary.BigEndian.Uint16(body[:2])); l <= len(list) {
				list = list[:l]
			}
			for i := 0; i+1 < len(list); i += 2 {
				sigs = append(sigs, binary.BigEndian.Uint16(list[i:i+2]))
			}
		}
		return
	}

	_, _, unpadded := walk(0)
	ids, sigs, _ := walk(unpadded)

	ids = append(ids, 0) // SNI: empty offline, always present in a real handshake
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var hashed []string
	for _, id := range ids {
		if id == 0 || id == 16 {
			continue // ja4 hashes neither SNI nor ALPN
		}
		hashed = append(hashed, fmt.Sprintf("%04x", id))
	}
	var sigStr []string
	for _, s := range sigs {
		if !isGreaseCode(s) {
			sigStr = append(sigStr, fmt.Sprintf("%04x", s))
		}
	}
	return hash12(strings.Join(ciphers, ",")) + "_" +
		hash12(strings.Join(hashed, ",")+"_"+strings.Join(sigStr, ",")), len(ids)
}

func TestGoldenJA4(t *testing.T) {
	off := false
	ids := make([]string, 0, len(goldenJA4))
	for id := range goldenJA4 {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			profile, err := BuildClientHelloSpec(id, &off)
			if err != nil {
				t.Fatalf("BuildClientHelloSpec(%s): %v", id, err)
			}
			got, n := ja4Of(t, profile, false)
			if want := goldenJA4[id]; got != want {
				t.Errorf("%s: ja4 body = %s (%d extensions), want %s", id, got, n, want)
			}
			// The extension count is part of the ja4 prefix, so a profile that gains
			// or loses one has to be re-measured, not just re-pinned.
			wantN := 16
			if id == "chrome_152" || id == "chrome_155" {
				wantN = 17
			}
			if n != wantN {
				t.Errorf("%s: %d extensions, want %d", id, n, wantN)
			}
		})
	}
}

// The Chrome 135 and 136 peet captures read t13d1516h2_8daaf6152771_fca9c764716e
// while 142 through 151 read ..._d8a2da3f94cd, and that difference is one extension
// id: 21, padding. Nothing else about the two captures differs - peetprint, the ja3
// extension list, ciphers, groups, key shares, ALPN and the akamai string are all
// identical - and peet's own extension array for the 136 capture does not list
// padding either, so the flag comes from peet's ja4 field, not from a Chrome byte.
// Switching TlsPadding on reproduces the hash exactly, which is what proves padding
// is the whole of it: apart from that id the built chrome_136 is byte-identical to
// chrome_143.
//
// Chrome is not expected to send the extension here at all: BoringSSL adds it only to
// pull a hello of 256 to 511 bytes up to 512, and recounting these captures' own
// extension lengths puts every one of them near 1.8 KB - 136 and 148 measure the same
// 1768 bytes, and only the 136 one is flagged. So Chrome_136 stays without
// TlsPadding and chrome_136 through chrome_149 stay one band. Reach for this test
// before splitting an anchor over a capture whose ja4 disagrees.
func TestPaddingIsTheOnlyChrome136Delta(t *testing.T) {
	plain := MappedTLSClients["chrome_136"]
	base, err := BuildClientHelloSpecWithCP(plain)
	if err != nil {
		t.Fatalf("chrome_136: %v", err)
	}
	if got, n := ja4Of(t, base, false); got != goldenJA4["chrome_136"] || n != 16 {
		t.Fatalf("chrome_136 without padding: %s (%d), want %s (16)", got, n, goldenJA4["chrome_136"])
	}

	padded := MappedTLSClients["chrome_136"]
	padded.TlsPadding = true
	withPadding, err := BuildClientHelloSpecWithCP(padded)
	if err != nil {
		t.Fatalf("chrome_136 with TlsPadding: %v", err)
	}
	got, n := ja4Of(t, withPadding, true)
	if want := "8daaf6152771_fca9c764716e"; got != want {
		t.Errorf("chrome_136 + padding: ja4 body = %s, want %s", got, want)
	}
	if n != 17 {
		t.Errorf("chrome_136 + padding: %d extensions, want 17", n)
	}
}
