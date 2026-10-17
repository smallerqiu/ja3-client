package ja3

import (
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"sort"
	"testing"

	tls "github.com/smallerqiu/utls"
)

// utls mutates the extension instances of the spec it is handed. Its own contract on
// ApplyPreset says so ("Fields of TLSExtensions that are slices/pointers are shared
// across different connections with same ClientHelloSpec. It is advised to use
// different specs and avoid any shared state."), and u_parrots.go skips key generation
// for a key share that still carries data:
//
//	case *KeyShareExtension: … if len(ext.KeyShares[i].Data) > 1 { continue }
//
// So a spec whose instances are reused for a second handshake goes out with the first
// handshake's public keys and then dies in handshake_client_tls13.go with
// "local error: tls: internal error" - the failure onlyfans.com reported, and the reason
// every SpecFactory here rebuilds. These tests pin that: fresh instances, empty key
// shares, and - because a rebuild must not silently change the fingerprint - the same
// extension order every time.

// extIds walks a spec offline and returns the extension ids in wire order, one entry per
// extension. Entries whose id cannot be read offline (SNI reports Len() == 0 until a
// server name exists, padding only learns its length from the unpadded hello) become -1,
// so the list is still positionally comparable between two builds of the same profile.
func extIds(spec tls.ClientHelloSpec) []int {
	ids := make([]int, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.UtlsGREASEExtension); ok {
			ids = append(ids, -1) // a fresh grease slot every build, by design
			continue
		}
		if _, ok := ext.(*tls.UtlsPaddingExtension); ok {
			ids = append(ids, -1)
			continue
		}
		n := ext.Len()
		if n < 4 {
			ids = append(ids, -1)
			continue
		}
		buf := make([]byte, n)
		ext.Read(buf) // utls returns the full length along with io.EOF
		ids = append(ids, int(binary.BigEndian.Uint16(buf[:2])))
	}
	return ids
}

// stateless reports whether an extension has no fields at all. Such a type has nothing
// for utls to mutate, and Go hands every zero-sized allocation the same address
// (runtime.zerobase), so pointer identity says nothing about them either way.
func stateless(ext tls.TLSExtension) bool {
	tp := reflect.TypeOf(ext)
	return tp.Kind() == reflect.Pointer && tp.Elem().Size() == 0
}

func ptrs(spec tls.ClientHelloSpec) map[string]bool {
	set := make(map[string]bool, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		if stateless(ext) {
			continue
		}
		set[fmt.Sprintf("%p", ext)] = true
	}
	return set
}

// checkSpecFreshness asserts one profile hands out a spec that is safe to shake with more
// than once.
func checkSpecFreshness(t *testing.T, name string, build func() (tls.ClientHelloSpec, error)) {
	t.Helper()
	first, err := build()
	if err != nil {
		t.Fatalf("%s: first build: %v", name, err)
	}
	second, err := build()
	if err != nil {
		t.Fatalf("%s: second build: %v", name, err)
	}

	shared := ptrs(first)
	for _, ext := range second.Extensions {
		if stateless(ext) {
			continue
		}
		if shared[fmt.Sprintf("%p", ext)] {
			t.Errorf("%s: extension instance %T is shared between two specs; "+
				"utls mutates it in place, so the second handshake reuses the first one's key material",
				name, ext)
			break
		}
	}

	a, b := extIds(first), extIds(second)
	if len(a) != len(b) {
		t.Fatalf("%s: extension count differs between builds: %d vs %d", name, len(a), len(b))
	}
	for i := range a {
		if a[i] == -1 || b[i] == -1 {
			continue // grease and offline-unreadable slots are allowed to differ
		}
		if a[i] != b[i] {
			t.Errorf("%s: extension order changed between builds at %d: %04x vs %04x", name, i, a[i], b[i])
			break
		}
	}
}

// TestSpecIsFreshPerHandshake covers the profiles the reported failures came through:
// chrome_153 (onlyfans), chrome_152 (its anchor, RandomExtensionOrder + ECH + trust
// anchors), chrome_136 (an older chrome shape), plus firefox and safari, whose extension
// sets and padding differ.
func TestSpecIsFreshPerHandshake(t *testing.T) {
	off := false
	for _, name := range []string{"chrome_153", "chrome_152", "chrome_136", "firefox_135", "safari_18_0"} {
		profile, err := BuildClientHelloSpec(name, &off)
		if err != nil {
			t.Fatalf("%s: BuildClientHelloSpec: %v", name, err)
		}
		t.Run(name, func(t *testing.T) {
			checkSpecFreshness(t, name, profile.GetClientHelloSpec)
		})
	}
}

// TestJa3KeySpecIsFreshPerHandshake covers the other SpecFactory, the one that rebuilds a
// profile out of a ja3 string.
func TestJa3KeySpecIsFreshPerHandshake(t *testing.T) {
	off := false
	const ja3key = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0"
	profile, err := BuildClientHelloSpecFromJa3Key(ja3key, "", &off)
	if err != nil {
		t.Fatalf("BuildClientHelloSpecFromJa3Key: %v", err)
	}
	checkSpecFreshness(t, "ja3key", profile.GetClientHelloSpec)
}

// TestSpecIsFreshAfterAHandshake is the regression test for the reported defect. A real
// handshake leaves its state on the spec's extension instances - utls fills the key shares
// while building the ClientHello - and a profile that hands the same instances out again
// sends those stale public keys, after which u_parrots.go's
// `if len(ext.KeyShares[i].Data) > 1 { continue }` skips regeneration and
// handshake_client_tls13.go aborts with "local error: tls: internal error". The handshake
// here is offline: BuildHandshakeState only builds the ClientHello, it does not need a
// server to answer.
func TestSpecIsFreshAfterAHandshake(t *testing.T) {
	off := false
	const ja3key = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0"
	cases := map[string]func() (ClientProfile, error){
		"chrome_153":  func() (ClientProfile, error) { return BuildClientHelloSpec("chrome_153", &off) },
		"chrome_152":  func() (ClientProfile, error) { return BuildClientHelloSpec("chrome_152", &off) },
		"firefox_135": func() (ClientProfile, error) { return BuildClientHelloSpec("firefox_135", &off) },
		"safari_18_0": func() (ClientProfile, error) { return BuildClientHelloSpec("safari_18_0", &off) },
		"ja3key":      func() (ClientProfile, error) { return BuildClientHelloSpecFromJa3Key(ja3key, "", &off) },
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			profile, err := cases[name]()
			if err != nil {
				t.Fatalf("build profile: %v", err)
			}
			buildClientHelloOffline(t, profile)

			spec, err := profile.GetClientHelloSpec()
			if err != nil {
				t.Fatalf("GetClientHelloSpec after the handshake: %v", err)
			}
			for _, ext := range spec.Extensions {
				ks, ok := ext.(*tls.KeyShareExtension)
				if !ok {
					continue
				}
				for _, share := range ks.KeyShares {
					if len(share.Data) > 1 {
						t.Errorf("%s: key share %x still holds %d bytes of the first handshake's public key; "+
							"the next handshake reuses it and aborts with an internal error",
							name, share.Group, len(share.Data))
					}
				}
			}
		})
	}
}

// buildClientHelloOffline runs one handshake's worth of utls work on a profile without a
// network: utls builds the ClientHello into uconn.HandshakeState.Hello.Raw and, along the
// way, writes the generated key shares into the spec's KeyShareExtension.
func buildClientHelloOffline(t *testing.T, profile ClientProfile) {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	id := profile.GetClientHelloId()
	uc := tls.UClient(client, &tls.Config{ServerName: "example.com"}, id, id.RandomExtensionOrder, false, nil)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
}

// TestEveryMappedProfileIsFresh runs the freshness check over the whole mapped set: a
// profile that reuses state is only a crash for whoever asks for it, and the mapped ids
// are the public surface.
func TestEveryMappedProfileIsFresh(t *testing.T) {
	off := false
	for id := range MappedTLSClients {
		profile, err := BuildClientHelloSpec(id, &off)
		if err != nil {
			t.Errorf("%s: BuildClientHelloSpec: %v", id, err)
			continue
		}
		t.Run(id, func(t *testing.T) {
			checkSpecFreshness(t, id, profile.GetClientHelloSpec)
		})
	}
}
