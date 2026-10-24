package ss

import (
	"bytes"
	"errors"
	"testing"
)

func TestInitialEOFDiagnosticDoesNotRelaxPolicy(t *testing.T) {
	for _, data := range [][]byte{nil, {1}} {
		_, e := server(t, AES128GCM2022).Accept(&memTransport{input: bytes.NewReader(data)})
		var h *HandshakeError
		if !errors.Is(e, ErrInitialRead) || !errors.As(e, &h) {
			t.Fatal("first Read policy changed", e)
		}
		if h.EmptyEOF() != (len(data) == 0) {
			t.Fatal("EOF diagnostic classification")
		}
	}
}
