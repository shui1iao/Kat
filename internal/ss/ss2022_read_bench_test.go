package ss

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// Identical in the baseline-bench and ss2022-up trees (Plan v3 S4): one SS2022
// record of 32734 plaintext bytes read by a 16384B caller (the relay buffer).
func BenchmarkSS2022Read32734Caller16384(b *testing.B) {
	m, e := lookup(AES128GCM2022)
	if e != nil {
		b.Fatal(e)
	}
	s, e := NewServer(Config{Method: AES128GCM2022, Key: bytes.Repeat([]byte{3}, m.keySize), UserID: "bench"})
	if e != nil {
		b.Fatal(e)
	}
	salt := bytes.Repeat([]byte{5}, m.keySize)
	a, e := s.aead(salt)
	if e != nil {
		b.Fatal(e)
	}
	const records = 64
	payload := bytes.Repeat([]byte{0x42}, 32734)
	var n counter
	var wire []byte
	for i := 0; i < records; i++ {
		l, _ := seal(a, &n, binary.BigEndian.AppendUint16(nil, uint16(len(payload))))
		p, _ := seal(a, &n, payload)
		wire = append(append(wire, l...), p...)
	}
	buf := make([]byte, 16384)
	src := bytes.NewReader(wire)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	var r *recordReader
	left := 0
	for i := 0; i < b.N; i++ {
		if left == 0 {
			b.StopTimer()
			src.Reset(wire)
			r = &recordReader{r: src, aead: a, max: MaxChunk2022}
			left = records
			b.StartTimer()
		}
		got := 0
		for got < len(payload) {
			k, e := r.Read(buf)
			if e != nil && e != io.EOF {
				b.Fatal(e)
			}
			got += k
		}
		left--
	}
}
