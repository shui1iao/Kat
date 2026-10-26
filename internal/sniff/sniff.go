// Package sniff extracts the destination domain from the first bytes of a
// connection: the TLS ClientHello SNI, the HTTP/1.x Host header and the SNI
// of a QUIC Initial packet (decrypted with the public Initial keys of QUIC
// v1, v2 and draft-29). It never writes and keeps no state between calls
// except in a QUIC assembler.
package sniff

import (
	"bytes"
	"net/netip"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// Status is the outcome of looking at a prefix of a stream.
type Status uint8

const (
	NotMatch Status = iota // not this protocol (or malformed): stop
	NeedMore               // a valid prefix: more bytes are needed
	Done                   // complete; Host may still be empty (no SNI)
)

// Protocol names used in routing.
const (
	ProtoTLS  = "tls"
	ProtoHTTP = "http"
	ProtoQUIC = "quic"
)

// MaxStream bounds how much of a TCP stream is buffered while sniffing.
const MaxStream = 16 << 10

// Stream classifies the first bytes b of a TCP stream.
func Stream(b []byte) (proto, host string, st Status) {
	if len(b) == 0 {
		return "", "", NeedMore
	}
	if b[0] == 0x16 {
		host, st = TLSClientHello(b)
		return ProtoTLS, host, st
	}
	host, st = HTTPHost(b)
	return ProtoHTTP, host, st
}

// TLSClientHello parses TLS records carrying a ClientHello (possibly spread
// over several handshake records) and returns its server_name.
func TLSClientHello(b []byte) (string, Status) {
	var hs []byte
	for {
		if len(b) < 5 {
			return "", NeedMore
		}
		if b[0] != 0x16 || b[1] != 3 || b[2] > 4 {
			return "", NotMatch
		}
		n := int(b[3])<<8 | int(b[4])
		if n == 0 || n > 1<<14+256 {
			return "", NotMatch
		}
		if len(b) < 5+n {
			// Enough of the first record to reject a non-ClientHello early.
			frag := b[5:]
			if len(hs) == 0 && len(frag) > 0 && frag[0] != 1 {
				return "", NotMatch
			}
			return "", NeedMore
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
		if len(hs) >= 4 {
			if hs[0] != 1 {
				return "", NotMatch
			}
			total := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if total > MaxStream {
				return "", NotMatch
			}
			if len(hs) >= total {
				return ClientHelloSNI(hs[:total])
			}
		}
	}
}

// ClientHelloSNI parses a complete handshake message (type 1).
func ClientHelloSNI(msg []byte) (string, Status) {
	s := cryptobyte.String(msg)
	var typ uint8
	var body cryptobyte.String
	if !s.ReadUint8(&typ) || typ != 1 || !s.ReadUint24LengthPrefixed(&body) {
		return "", NotMatch
	}
	var ver uint16
	var random, sid, suites, comp cryptobyte.String
	if !body.ReadUint16(&ver) || !body.ReadBytes((*[]byte)(&random), 32) ||
		!body.ReadUint8LengthPrefixed(&sid) || !body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&comp) {
		return "", NotMatch
	}
	if body.Empty() {
		return "", Done
	}
	var exts cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&exts) {
		return "", NotMatch
	}
	for !exts.Empty() {
		var et uint16
		var ed cryptobyte.String
		if !exts.ReadUint16(&et) || !exts.ReadUint16LengthPrefixed(&ed) {
			return "", NotMatch
		}
		if et != 0 {
			continue
		}
		var list cryptobyte.String
		if !ed.ReadUint16LengthPrefixed(&list) {
			return "", NotMatch
		}
		for !list.Empty() {
			var nt uint8
			var name cryptobyte.String
			if !list.ReadUint8(&nt) || !list.ReadUint16LengthPrefixed(&name) {
				return "", NotMatch
			}
			if nt == 0 {
				return domainOnly(string(name)), Done
			}
		}
	}
	return "", Done
}

var methods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

const maxHTTPHead = 8 << 10

// HTTPHost parses an HTTP/1.x request head and returns the Host header.
func HTTPHost(b []byte) (string, Status) {
	matched := false
	for _, m := range methods {
		n := min(len(b), len(m))
		if string(b[:n]) == m[:n] {
			if n < len(m) {
				return "", NeedMore
			}
			matched = true
			break
		}
	}
	if !matched {
		return "", NotMatch
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	head := b
	if end >= 0 {
		head = b[:end+2]
	} else if len(b) > maxHTTPHead {
		return "", NotMatch
	}
	// Request line must be complete and name HTTP/1.x.
	i := bytes.Index(head, []byte("\r\n"))
	if i < 0 {
		if end < 0 {
			return "", NeedMore
		}
		return "", NotMatch
	}
	if !bytes.Contains(head[:i], []byte(" HTTP/1.")) {
		return "", NotMatch
	}
	for line := head[i+2:]; len(line) > 0; {
		j := bytes.Index(line, []byte("\r\n"))
		if j < 0 {
			break // incomplete header line
		}
		h := line[:j]
		line = line[j+2:]
		k := bytes.IndexByte(h, ':')
		if k < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(h[:k])), "host") {
			v := strings.TrimSpace(string(h[k+1:]))
			return domainOnly(stripPort(v)), Done
		}
	}
	if end >= 0 {
		return "", Done
	}
	return "", NeedMore
}

func stripPort(v string) string {
	if strings.HasPrefix(v, "[") {
		if i := strings.IndexByte(v, ']'); i > 0 {
			return v[1:i]
		}
		return ""
	}
	if i := strings.LastIndexByte(v, ':'); i >= 0 && strings.Count(v, ":") == 1 {
		return v[:i]
	}
	return v
}

// domainOnly returns the lower-case name without trailing dot, or "" for IP
// literals and names that are not plain DNS names.
func domainOnly(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 {
		return ""
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return ""
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return ""
		}
		for k := 0; k < len(l); k++ {
			c := l[k]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return s
}
