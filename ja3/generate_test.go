package ja3

import (
	"fmt"
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
