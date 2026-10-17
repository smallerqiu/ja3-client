package ja3

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func TestBuildClientHelloSpec(t *testing.T) {
	spec, err := buildHttp2Spec("1:65536;2:0;4:6291456;6:262144|15663105|0")
	spec, err = buildHttp2Spec("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
	if err != nil {
		return
	}
	fmt.Println(spec)
}

// The three default knobs have to agree with each other. `DefaultImpersonate` names a
// map entry, `DefaultClient` is the ClientData the fallback in BuildClientHelloSpec uses,
// and `DefaultClientProfile` is built from the name - so a change to one of them without
// the others makes "no impersonate set" mean two different fingerprints depending on
// which code path a caller takes, silently. This bites: moving DefaultImpersonate to a
// name that is not in MappedTLSClients, or pointing DefaultClient at another band, fails
// here instead of only in a log line.
func TestDefaultProfileIsSelfConsistent(t *testing.T) {
	mapped, ok := MappedTLSClients[DefaultImpersonate]
	if !ok {
		t.Fatalf("DefaultImpersonate %q is not in MappedTLSClients - a caller who sets "+
			"nothing silently gets the fallback and never sees the typo", DefaultImpersonate)
	}

	want, err := BuildClientHelloSpecWithCP(mapped)
	if err != nil {
		t.Fatalf("BuildClientHelloSpecWithCP(%s): %v", DefaultImpersonate, err)
	}
	got, err := BuildClientHelloSpecWithCP(DefaultClient)
	if err != nil {
		t.Fatalf("BuildClientHelloSpecWithCP(DefaultClient): %v", err)
	}

	wantSpec, err := want.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("%s spec: %v", DefaultImpersonate, err)
	}
	gotSpec, err := got.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("DefaultClient spec: %v", err)
	}

	// Compared as sets, not sequences: Chrome has randomized the extension order since
	// 110, so two independent builds of the same profile legitimately differ in order
	// (see the deviations list in CONTRIBUTING.md). The membership is what says which
	// band a default belongs to - chrome_155's anchor sends trust_anchors (51764),
	// chrome_141's never did.
	if a, b := idSet(extIds(wantSpec)), idSet(extIds(gotSpec)); !reflect.DeepEqual(a, b) {
		t.Errorf("DefaultClient extension set = %v, want %v (the %s mapping)", b, a, DefaultImpersonate)
	}
	if !reflect.DeepEqual(sortedUints(wantSpec.CipherSuites), sortedUints(gotSpec.CipherSuites)) {
		t.Errorf("DefaultClient cipher set differs from the %s mapping", DefaultImpersonate)
	}
	if DefaultClient.UserAgent != mapped.UserAgent {
		t.Errorf("DefaultClient User-Agent = %q, want %q", DefaultClient.UserAgent, mapped.UserAgent)
	}

	// session.go reads DefaultClient.UserAgent for its "no profile chosen" signal, and
	// client.go hands callers DefaultClientProfile, so two defaults drifting apart would
	// give a caller a User-Agent that belongs to another fingerprint.
	if DefaultClientProfile.GetUserAgent() != mapped.UserAgent {
		t.Errorf("DefaultClientProfile User-Agent = %q, want %q",
			DefaultClientProfile.GetUserAgent(), mapped.UserAgent)
	}
}

// Every id in MappedTLSClients has to build a spec offline. A UA-only block is
// three lines of code and a typo in one of them - an unknown curve, a weight over
// 255, a scheme with no name - otherwise only shows up when someone asks for that
// profile and the library returns the default with a log line.
func TestEveryMappedProfileBuilds(t *testing.T) {
	off := false
	ids := make([]string, 0, len(MappedTLSClients))
	for id := range MappedTLSClients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		profile, err := BuildClientHelloSpec(id, &off)
		if err != nil {
			t.Errorf("%s: BuildClientHelloSpec: %v", id, err)
			continue
		}
		if profile.GetUserAgent() == "" {
			t.Errorf("%s: empty UserAgent", id)
		}
		if _, err := profile.GetClientHelloSpec(); err != nil {
			t.Errorf("%s: GetClientHelloSpec: %v", id, err)
		}
	}
}

// idSet counts extension ids, GREASE slots (read as -1) included: profiles in different
// bands differ by membership, and how many GREASE slots a hello carries is part of shape.
func idSet(ids []int) map[int]int {
	counted := map[int]int{}
	for _, id := range ids {
		counted[id]++
	}
	return counted
}

func sortedUints(in []uint16) []uint16 {
	out := append([]uint16(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
