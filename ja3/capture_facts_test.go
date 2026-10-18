package ja3

import (
	"encoding/binary"
	"sort"
	"strconv"
	"strings"
	"testing"

	tls "github.com/smallerqiu/utls"
)

// ja4 hashes a sorted extension set, a sorted cipher list and the signature algorithms,
// so four things a capture can disagree on are invisible to TestGoldenJA4: what goes in
// supported_versions, which groups key_share actually carries, whether session_ticket is
// offered, and the order of the ALPN list. The 2026-10-18 captures under client_data/
// (gitignored) turned all four into profile fields - NoTlsSessionTicket,
// TlsKeySharesLimit, ALPSS and TlsVersion - so they are pinned here against what those
// browsers sent.
//
// GREASE is dropped from every list rather than asserted: its value is chosen per
// handshake, and utls only fills it in when a connection is built.

// extBody returns the payload of the first extension with this id, or nil when the spec
// does not carry it. An extension with nothing to write reports Len() == 0 (SNI before a
// server name exists), and the GREASE slots read as 0000 offline, so both are skipped.
func extBody(spec tls.ClientHelloSpec, id uint16) []byte {
	for _, ext := range spec.Extensions {
		n := ext.Len()
		if n < 4 {
			continue
		}
		buf := make([]byte, n)
		read, _ := ext.Read(buf) // utls returns the full length along with io.EOF
		if binary.BigEndian.Uint16(buf[:2]) != id {
			continue
		}
		body := buf[4:read]
		if l := int(binary.BigEndian.Uint16(buf[2:4])); l <= len(body) {
			body = body[:l]
		}
		return body
	}
	return nil
}

// wireVersions reads supported_versions: a one-byte length, then that many two-byte ids.
func wireVersions(body []byte) []uint16 {
	if len(body) < 1 {
		return nil
	}
	var out []uint16
	list := body[1:]
	if n := int(body[0]); n <= len(list) {
		list = list[:n]
	}
	for i := 0; i+1 < len(list); i += 2 {
		v := binary.BigEndian.Uint16(list[i : i+2])
		if !isGreaseCode(v) {
			out = append(out, v)
		}
	}
	return out
}

// wireKeyShares reads key_share: a two-byte total length, then [group:2][length:2][data].
func wireKeyShares(body []byte) []uint16 {
	if len(body) < 2 {
		return nil
	}
	var out []uint16
	list := body[2:]
	if n := int(binary.BigEndian.Uint16(body[:2])); n <= len(list) {
		list = list[:n]
	}
	for i := 0; i+3 < len(list); {
		group := binary.BigEndian.Uint16(list[i : i+2])
		dataLen := int(binary.BigEndian.Uint16(list[i+2 : i+4]))
		i += 4 + dataLen
		if !isGreaseCode(group) {
			out = append(out, group)
		}
	}
	return out
}

// wireAlpn reads the ALPN list: a two-byte total length, then length-prefixed strings, in
// the order they go out - which is what ALPSS exists to control.
func wireAlpn(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	var out []string
	list := body[2:]
	if n := int(binary.BigEndian.Uint16(body[:2])); n <= len(list) {
		list = list[:n]
	}
	for i := 0; i < len(list); {
		l := int(list[i])
		start := i + 1
		i = start + l
		if l <= 0 || i > len(list) {
			break
		}
		out = append(out, string(list[start:i]))
	}
	return out
}

type capturedHello struct {
	versions      string // supported_versions from the capture, GREASE dropped, comma-separated
	keyShares     string // key_share groups, GREASE dropped, colon-separated; "" to skip
	alpn          string // ALPN protocols, in order
	sessionTicket bool   // whether extension 35 is on the wire
	recordSize    int    // record_size_limit as the capture prints it; 0 to skip
}

// The expectations below are read off the client_data/ captures of 2026-10-18, not off the
// profiles: safari/mac_26.5.json, firefox/144.json, firefox/153.json, qq/19.4.0.json,
// qq/22.1.json, uc/pc_1.1.json, edge/143.json, edge/151.json, edge/152.json,
// opera/137.json, brave/1.97.json and chrome/155.json. An empty keyShares (or a recordSize
// of 0) means the library does not match the capture on that fact yet - pinning the wrong
// value here would only freeze the deviation, so it is left to CONTRIBUTING instead.

var capturedHellos = map[string]capturedHello{
	// Safari 26.5 stops at TLS 1.2 and offers no session_ticket. That single extension
	// leaving the set, and the two legacy versions next to it, are the whole reason
	// Safari_26_5 is its own anchor instead of a c() line on Safari_26_0.
	"safari_26_5": {"772,771", "4588:29", "h2,http/1.1", false, 0},
	// QQ 19.4 sends one real key share next to its GREASE entry. The default limit of three
	// puts two real groups on the wire, because the GREASE slot is counted against the limit.
	"qq_19_4":    {"772,771", "29", "h2,http/1.1", true, 0},
	"qq_22_1":    {"772,771", "4588:29", "h2,http/1.1", true, 0},
	"chrome_155": {"772,771", "4588:29", "h2,http/1.1", true, 0},
	// UC PC advertises http/1.1 before h2, which is what ALPSS is for, and offers x25519
	// alone in key_share while supported_groups still lists the curve set behind it.
	"uc_pc_1_1": {"772,771", "29", "http/1.1,h2", true, 0},
	// The Chromium forks ride their Chrome band, so a mapping that drifts off its anchor
	// shows up here as a wrong key-share set or version list.
	"brave_1_97": {"772,771", "4588:29", "h2,http/1.1", true, 0},
	"opera_137":  {"772,771", "4588:29", "h2,http/1.1", true, 0},
	"edge_143":   {"772,771", "4588:29", "h2,http/1.1", true, 0},
	"edge_151":   {"772,771", "4588:29", "h2,http/1.1", true, 0},
	"edge_152":   {"772,771", "4588:29", "h2,http/1.1", true, 0},
	// Firefox offers three groups in key_share and no GREASE entry there; utls spends the
	// first slot of TlsKeySharesLimit on GREASE, so the profile sends two. Both firefox_144
	// and firefox_153 ride that deviation, which is why keyShares is empty. The versions and
	// the ALPN list are the capture's own and are asserted. recordSize tells the two apart:
	// firefox_153 sends the captured 16385, while firefox_144 still sends 4001 and is left
	// unchecked so a fix for the older ids stays a decision rather than a frozen fact.
	"firefox_144": {"772,771", "", "h2,http/1.1", true, 0},
	"firefox_153": {"772,771", "", "h2,http/1.1", true, 16385},
}

func TestCapturedHelloFacts(t *testing.T) {
	off := false
	ids := make([]string, 0, len(capturedHellos))
	for id := range capturedHellos {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			want := capturedHellos[id]
			profile, err := BuildClientHelloSpec(id, &off)
			if err != nil {
				t.Fatalf("BuildClientHelloSpec(%s): %v", id, err)
			}
			spec, err := profile.GetClientHelloSpec()
			if err != nil {
				t.Fatalf("GetClientHelloSpec: %v", err)
			}
			if got := join16(wireVersions(extBody(spec, tls.ExtensionSupportedVersions)), ","); got != want.versions {
				t.Errorf("%s: supported_versions = %s, want %s (TlsVersion)", id, got, want.versions)
			}
			if want.keyShares != "" {
				if got := join16(wireKeyShares(extBody(spec, tls.ExtensionKeyShare)), ":"); got != want.keyShares {
					t.Errorf("%s: key_share groups = %s, want %s (TlsKeySharesLimit, and the GREASE "+
						"slot counts against it when TlsGrease is on)", id, got, want.keyShares)
				}
			}
			if got := strings.Join(wireAlpn(extBody(spec, tls.ExtensionALPN)), ","); got != want.alpn {
				t.Errorf("%s: alpn = %s, want %s (ALPSS)", id, got, want.alpn)
			}
			offered := false
			for _, e := range extIds(spec) {
				if e == int(tls.ExtensionSessionTicket) {
					offered = true
				}
			}
			if offered != want.sessionTicket {
				t.Errorf("%s: session_ticket offered = %t, want %t (NoTlsSessionTicket)",
					id, offered, want.sessionTicket)
			}
			if want.recordSize != 0 {
				body := extBody(spec, tls.ExtensionRecordSizeLimit)
				got := 0
				if len(body) == 2 {
					got = int(binary.BigEndian.Uint16(body))
				}
				if got != want.recordSize {
					t.Errorf("%s: record_size_limit = %d, want %d (%s; the capture prints the decimal, "+
						"so a value copied from peet's hex needs the same base as the field)",
						id, got, want.recordSize, "TlsRecordSizeLimit")
				}
			}
		})
	}
}

// join16 renders the decoded ids the way the capture writes them: decimal, separated by
// sep ("," for supported_versions and ALPN, ":" for the key_share group list).
func join16(v []uint16, sep string) string {
	parts := make([]string, 0, len(v))
	for _, i := range v {
		parts = append(parts, strconv.FormatUint(uint64(i), 10))
	}
	return strings.Join(parts, sep)
}
