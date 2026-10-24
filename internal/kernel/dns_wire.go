package kernel

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"strings"
	"time"
)

var errDNS = errors.New("DNS lookup failed")

const maxDNSMessage = 65535
const maxDNSAddresses = 16

type dnsAnswer struct {
	ips       []netip.Addr
	ttl       time.Duration
	truncated bool
}

func dnsQuestion(name string, typ dnsmessage.Type) ([]byte, dnsmessage.Question, error) {
	n, e := dnsmessage.NewName(name + ".")
	if e != nil {
		return nil, dnsmessage.Question{}, errDNS
	}
	q := dnsmessage.Question{Name: n, Type: typ, Class: dnsmessage.ClassINET}
	var id [2]byte
	if _, e = rand.Read(id[:]); e != nil {
		return nil, q, errDNS
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{q}}
	b, e := m.Pack()
	return b, q, e
}
func parseDNSAnswer(w []byte, id uint16, q dnsmessage.Question) (dnsAnswer, error) {
	var out dnsAnswer
	if len(w) < 12 || len(w) > maxDNSMessage {
		return out, errDNS
	}
	var parser dnsmessage.Parser
	h, e := parser.Start(w)
	if e != nil || !h.Response || h.ID != id || h.OpCode != 0 || h.RCode != dnsmessage.RCodeSuccess {
		return out, errDNS
	}
	qs, e := parser.AllQuestions()
	if e != nil || len(qs) != 1 {
		return out, errDNS
	}
	p := qs[0]
	if !strings.EqualFold(p.Name.String(), q.Name.String()) || p.Type != q.Type || p.Class != q.Class {
		return out, errDNS
	}
	if h.Truncated {
		out.truncated = true
		return out, nil
	}
	var m dnsmessage.Message
	if m.Unpack(w) != nil {
		return out, errDNS
	}
	name := strings.ToLower(q.Name.String())
	ttl := uint32(300)
	minTTL := func(v uint32) {
		if v < ttl {
			ttl = v
		}
	}
	// Only answers connected to the question by a bounded CNAME chain are usable.
	seen := map[string]bool{}
	for depth := 0; ; depth++ {
		if seen[name] || depth > 8 {
			return out, errDNS
		}
		seen[name] = true
		var cname string
		found := false
		for _, r := range m.Answers {
			if r.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(r.Header.Name.String(), name) {
				continue
			}
			switch b := r.Body.(type) {
			case *dnsmessage.CNAMEResource:
				if cname != "" && !strings.EqualFold(cname, b.CNAME.String()) {
					return out, errDNS
				}
				cname = strings.ToLower(b.CNAME.String())
				minTTL(r.Header.TTL)
			case *dnsmessage.AResource:
				if q.Type == dnsmessage.TypeA {
					if len(out.ips) >= maxDNSAddresses {
						return out, errDNS
					}
					out.ips = append(out.ips, netip.AddrFrom4(b.A))
					minTTL(r.Header.TTL)
					found = true
				}
			case *dnsmessage.AAAAResource:
				if q.Type == dnsmessage.TypeAAAA {
					if len(out.ips) >= maxDNSAddresses {
						return out, errDNS
					}
					out.ips = append(out.ips, netip.AddrFrom16(b.AAAA).Unmap())
					minTTL(r.Header.TTL)
					found = true
				}
			}
		}
		if found {
			if cname != "" {
				return out, errDNS
			}
			out.ttl = time.Duration(ttl) * time.Second
			return out, nil
		}
		if cname == "" {
			return out, nil
		}
		name = cname
	}
}
