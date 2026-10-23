package ss

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func TestUDP2017DerivationAndWireParity(t *testing.T) {
	for _, name := range methods[:3] {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			old := server(t, name)
			request := &Packet{owner: s, source: testPeer}

			for i := 0; i < 32; i++ {
				salt := seq(i+17, s.m.keySize)
				reference, e := deriveAEAD(s.m, s.key, salt)
				if e != nil {
					t.Fatal(e)
				}
				current, e := s.aead2017UDP(salt)
				if e != nil {
					t.Fatal(e)
				}
				data := bytes.Repeat([]byte{byte(i)}, 1200)
				var nonce [12]byte
				a, b := reference.Seal(nil, nonce[:], data, nil), current.Seal(nil, nonce[:], data, nil)
				if !bytes.Equal(a, b) {
					t.Fatal("HKDF/AEAD wire changed")
				}
				if p, e := reference.Open(nil, nonce[:], b, nil); e != nil || !bytes.Equal(p, data) {
					t.Fatal("new ciphertext incompatible", e)
				}
				s.random = bytes.NewReader(salt)
				old.random = bytes.NewReader(salt)
				got, peer, e := s.EncodeUDP(request, testTarget, data)
				if e != nil {
					t.Fatal(e)
				}
				outSalt, e := old.responseSalt()
				if e != nil {
					t.Fatal(e)
				}
				ae, e := old.aead(outSalt)
				if e != nil {
					t.Fatal(e)
				}
				address, _ := testTarget.MarshalBinary()
				body := append(address, data...)
				want := append(outSalt, ae.Seal(nil, nonce[:], body, nil)...)
				if peer != testPeer || !bytes.Equal(got, want) {
					t.Fatal("response changed", name, i)
				}
				before := bytes.Clone(got)
				clear(data)
				if !bytes.Equal(before, got) {
					t.Fatal("response aliases caller input")
				}
			}
			if s.Stats().Salts2017 != old.Stats().Salts2017 {
				t.Fatal("salt security accounting changed")
			}
		})
	}
}
func BenchmarkUDP2017KDF(b *testing.B) {
	m, _ := lookup(AES128GCM)
	s, _ := NewServer(Config{Method: AES128GCM, Key: seq(0, 16)})
	salt := seq(33, 16)
	for _, kind := range []string{"reader", "one-shot"} {
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var a cipher.AEAD
				var e error
				if kind == "reader" {
					a, e = deriveAEAD(m, s.key, salt)
				} else {
					a, e = s.aead2017UDP(salt)
				}
				if e != nil || a == nil {
					b.Fatal(e)
				}
			}
		})
	}
}

func BenchmarkUDP2017ResponseBuffers(b *testing.B){
 s,_:=NewServer(Config{Method:AES128GCM,Key:seq(0,16)});salt:=seq(33,16);a,_:=s.aead(salt);payload:=make([]byte,1200);var nonce [12]byte
 for _,kind:=range []string{"old-three-buffers","one-wire"}{b.Run(kind,func(b *testing.B){b.ReportAllocs();var wire []byte
 for i:=0;i<b.N;i++{address,_:=testTarget.MarshalBinary();if kind=="old-three-buffers"{body:=append(address,payload...);wire=append(salt[:len(salt):len(salt)],a.Seal(nil,nonce[:],body,nil)...)}else{start:=len(salt);wire=make([]byte,start+len(address)+len(payload)+a.Overhead());copy(wire,salt);copy(wire[start:],address);copy(wire[start+len(address):],payload);wire=a.Seal(wire[:start],nonce[:],wire[start:len(wire)-a.Overhead()],nil)}}
 if len(wire)==0{b.Fatal("missing wire")}
 })}
}
