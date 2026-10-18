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

// TestHttp2PrioritiesParse pins the HTTP/2 priority frames of the three Firefox lines
// that still send them, because they are the only profiles whose akamai fingerprint
// depends on more than SETTINGS - and because browserleaks stopped printing the
// dependency: since 2026-10-18 it renders the priority section as "stream:weight" and
// hashes that, so its akamai_hash can no longer tell a lost StreamDep from a correct
// one. peet still prints the canonical four fields (tests/ TestOne asserts that hash),
// and this is the offline half: the profile string is StreamID:StreamDep:Exclusive:
// Weight, so a parser that drops or reorders a field fails here instead of only in a
// live run.
func TestHttp2PrioritiesParse(t *testing.T) {
	type pri struct {
		stream uint32
		dep    uint32
		excl   bool
		weight uint8
	}
	want := []pri{
		{3, 0, false, 200},
		{5, 0, false, 100},
		{7, 0, false, 0},
		{9, 7, false, 0},
		{11, 3, false, 0},
		{13, 0, false, 240},
	}

	for _, id := range []string{"firefox_117", "firefox_120", "firefox_123"} {
		profile, err := BuildClientHelloSpec(id, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := profile.GetPriorities()
		if len(got) != len(want) {
			t.Fatalf("%s: %d priority frames, want %d", id, len(got), len(want))
		}
		for i, w := range want {
			p := got[i]
			if p.StreamID != w.stream || p.PriorityParam.StreamDep != w.dep ||
				p.PriorityParam.Exclusive != w.excl || p.PriorityParam.Weight != w.weight {
				t.Errorf("%s priority %d = {stream %d dep %d excl %v weight %d}, want {stream %d dep %d excl %v weight %d}",
					id, i, p.StreamID, p.PriorityParam.StreamDep, p.PriorityParam.Exclusive, p.PriorityParam.Weight,
					w.stream, w.dep, w.excl, w.weight)
			}
		}
	}

	// Every other line must send none: Chrome dropped priority frames and Firefox did too
	// after 129, so a profile that grew a set would score an akamai hash no browser does.
	for _, id := range []string{"firefox_132", "firefox_135", "firefox_153", "chrome_155", "safari_26_5"} {
		profile, err := BuildClientHelloSpec(id, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := profile.GetPriorities(); len(got) != 0 {
			t.Errorf("%s: %d priority frames, want none", id, len(got))
		}
	}
}
