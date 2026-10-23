//go:build !linux

package kernel

import (
	"errors"
	"testing"
)

func TestSS2017RcvBufUnsupportedPlatform(t *testing.T) {
	in := Inbound{Protocol: "shadowsocks", Listen: "127.0.0.1:0", SS: &SSOptions{Method: "aes-128-gcm", Password: "x", UDPRcvBuf2017: ss2017RcvBufActual}}
	if e := (&Config{Inbounds: []Inbound{in}}).Validate(); !errors.Is(e, errSSRcvBufUnsupported) {
		t.Fatal("want explicit unsupported, got", e)
	}
	if _, _, _, e := setSS2017RcvBuf(nil, ss2017RcvBufActual); !errors.Is(e, errSSRcvBufUnsupported) {
		t.Fatal(e)
	}
}
