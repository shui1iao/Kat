package kernel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/shui1iao/Kat/internal/route"
)

// SniffOptions enables traffic sniffing on one inbound (0.7.0). The sniffed
// domain (TLS SNI, HTTP Host, QUIC SNI) and protocol are used by the rules;
// with override_destination an IP destination is replaced by the domain and
// resolved by the server.
type SniffOptions struct {
	Enabled             bool     `json:"enabled"`
	TCPPorts            string   `json:"tcp_ports,omitempty"` // default 80,443,8080,8443; "none" disables
	UDPPorts            string   `json:"udp_ports,omitempty"` // default 443; "none" disables
	Timeout             Duration `json:"timeout,omitempty"`   // first-data wait, default 300ms
	OverrideDestination bool     `json:"override_destination,omitempty"`

	tcp, udp route.PortList
}

const (
	defaultSniffTCPPorts = "80,443,8080,8443"
	defaultSniffUDPPorts = "443"
	defaultSniffTimeout  = 300 * time.Millisecond
	maxSniffTimeout      = 2 * time.Second
)

func (o *SniffOptions) normalize() error {
	parse := func(s *string, def string, dst *route.PortList) error {
		if *s == "" {
			*s = def
		}
		if *s == "none" {
			*dst = nil
			return nil
		}
		l, ok := route.ParsePorts(*s)
		if !ok {
			return errors.New("sniff ports must be ports, ranges a-b or a list of them (or none)")
		}
		*dst = l
		return nil
	}
	if e := parse(&o.TCPPorts, defaultSniffTCPPorts, &o.tcp); e != nil {
		return e
	}
	if e := parse(&o.UDPPorts, defaultSniffUDPPorts, &o.udp); e != nil {
		return e
	}
	if o.Timeout == 0 {
		o.Timeout = Duration(defaultSniffTimeout)
	}
	if o.Timeout.value() < time.Millisecond || o.Timeout.value() > maxSniffTimeout {
		return errors.New("sniff timeout must be between 1ms and 2s")
	}
	return nil
}

// sniffTCP reports whether a TCP stream to port is sniffed on this inbound.
func (in *Inbound) sniffTCP(port uint16) bool {
	return in.Sniff != nil && in.Sniff.Enabled && in.Sniff.tcp.Contains(port)
}

// validateInboundRefs checks inbound names, sniff options and that every
// in_name rule refers to a named inbound.
func (c *Config) validateInboundRefs(ro route.Options) error {
	names := map[string]bool{}
	for i := range c.Inbounds {
		in := &c.Inbounds[i]
		if in.Name != "" {
			if !validOutboundName(in.Name) || names[in.Name] {
				return fmt.Errorf("inbound %d: invalid or duplicate name", i)
			}
			names[in.Name] = true
		}
		if in.Sniff != nil {
			if e := in.Sniff.normalize(); e != nil {
				return fmt.Errorf("inbound %d: %v", i, e)
			}
		}
	}
	for _, n := range ro.ReferencedInboundNames() {
		if !names[n] {
			return fmt.Errorf("routing: in_name %q is not the name of an inbound", n)
		}
	}
	return nil
}

// inboundMeta carries the routing attributes of the accepting inbound.
type inboundMeta struct {
	name, typ string
	port      uint16
	srcPort   uint16
	sniff     *SniffOptions // nil or disabled: no sniffing
}

type inMetaKey struct{}

// withInboundMeta attaches the inbound's name, type, local port (from the
// accepted socket, so port 0 listeners report the real port) and sniffing.
func withInboundMeta(ctx context.Context, in *Inbound, local, remote net.Addr) context.Context {
	m := &inboundMeta{name: in.Name, typ: in.Protocol, srcPort: addrPort(remote).Port()}
	if a := addrPort(local); a.IsValid() {
		m.port = a.Port()
	} else if _, p, e := net.SplitHostPort(in.Listen); e == nil {
		n, _ := strconv.Atoi(p)
		m.port = uint16(n)
	}
	if in.Sniff != nil && in.Sniff.Enabled {
		m.sniff = in.Sniff
	}
	return context.WithValue(ctx, inMetaKey{}, m)
}

// listenerSlot is the reload identity of inbound i of inbounds: its listen
// key, with port 0 listeners numbered per address as reload numbers them.
func listenerSlot(inbounds []Inbound, i int) string {
	key := listenKey(inbounds[i].Listen)
	if !ephemeralPort(key) {
		return key
	}
	n := 0
	for j := 0; j < i; j++ {
		if listenKey(inbounds[j].Listen) == key {
			n++
		}
	}
	return key + "#" + strconv.Itoa(n)
}

// currentInboundMeta gives a stream of a session accepted by an older
// generation (AnyTLS) the inbound attributes (name, sniffing) of the current
// generation's inbound on the same listener, as its routing is the current
// one. Without such an inbound the accepting attributes stay.
func (s *Server) currentInboundMeta(ctx context.Context, acc *Server) context.Context {
	m := inboundMetaOf(ctx)
	i := inboundOf(ctx)
	if m == nil || s == acc || i < 0 || i >= len(acc.cfg.Inbounds) {
		return ctx
	}
	slot := listenerSlot(acc.cfg.Inbounds, i)
	for j := range s.cfg.Inbounds {
		in := &s.cfg.Inbounds[j]
		if in.Protocol != m.typ || listenerSlot(s.cfg.Inbounds, j) != slot {
			continue
		}
		n := *m
		n.name, n.sniff = in.Name, nil
		if in.Sniff != nil && in.Sniff.Enabled {
			n.sniff = in.Sniff
		}
		return context.WithValue(ctx, inMetaKey{}, &n)
	}
	return ctx
}

func inboundMetaOf(ctx context.Context) *inboundMeta {
	m, _ := ctx.Value(inMetaKey{}).(*inboundMeta)
	return m
}

func addrPort(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		if v != nil {
			return v.AddrPort()
		}
	case *net.UDPAddr:
		if v != nil {
			return v.AddrPort()
		}
	case nil:
	default:
		if ap, e := netip.ParseAddrPort(a.String()); e == nil {
			return ap
		}
	}
	return netip.AddrPort{}
}
