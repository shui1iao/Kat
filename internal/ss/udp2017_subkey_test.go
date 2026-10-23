package ss

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha1"
	"sync"
	"testing"
)

func TestUDP2017FixedHKDFExact(t *testing.T) {
	for _, size := range []int{16, 32} {
		for seed := 0; seed < 256; seed++ {
			key := make([]byte, size)
			salt := make([]byte, size)
			for i := range key {
				key[i] = byte(seed + i*7)
				salt[i] = byte(seed*3 + i*13)
			}
			beforeKey, beforeSalt := bytes.Clone(key), bytes.Clone(salt)
			want, e := hkdf.Key(sha1.New, key, salt, "ss-subkey", size)
			if e != nil {
				t.Fatal(e)
			}
			got := make([]byte, size)
			udp2017Subkey(key, salt, got)
			if !bytes.Equal(got, want) {
				t.Fatalf("size%d seed%d mismatch", size, seed)
			}
			if !bytes.Equal(key, beforeKey) || !bytes.Equal(salt, beforeSalt) {
				t.Fatal("caller material modified")
			}
		}
	}
}
func TestUDP2017FixedHKDFConcurrentAndInvalid(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for _, size := range []int{16, 32} {
				key := bytes.Repeat([]byte{byte(g)}, size)
				salt := bytes.Repeat([]byte{byte(g + 10)}, size)
				want, _ := hkdf.Key(sha1.New, key, salt, "ss-subkey", size)
				for i := 0; i < 64; i++ {
					got := make([]byte, size)
					udp2017Subkey(key, salt, got)
					if !bytes.Equal(got, want) {
						t.Error("shared key state")
					}
				}
			}
		}(g)
	}
	wg.Wait()
	for _, name := range methods[:3] {
		s := server(t, name)
		for _, n := range []int{0, 1, 15, 17, 31, 33, 65} {
			if n == s.m.keySize {
				continue
			}
			if _, e := s.aead2017UDP(make([]byte, n)); e != ErrKey {
				t.Fatal("invalid length", name, n, e)
			}
		}
	}
}
func BenchmarkUDP2017FixedHKDF(b *testing.B) {
	for _, size := range []int{16, 32} {
		key, salt := make([]byte, size), make([]byte, size)
		name := "aes128"
		if size == 32 {
			name = "aes256-chacha"
		}
		b.Run(name+"/stdlib", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sub, e := hkdf.Key(sha1.New, key, salt, "ss-subkey", size)
				if e != nil {
					b.Fatal(e)
				}
				clear(sub)
			}
		})
		b.Run(name+"/fixed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var out [32]byte
				udp2017Subkey(key, salt, out[:size])
				clear(out[:])
			}
		})
	}
}
