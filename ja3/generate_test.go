package ja3

import (
	"fmt"
	"testing"
)

func TestBuildClientHelloSpec(t *testing.T) {
	spec, err := buildHttp2Spec("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
	spec, err = buildHttp2Spec("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
	if err != nil {
		return
	}
	fmt.Println(spec)
}
