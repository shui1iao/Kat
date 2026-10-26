package kernel

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// SOCKS5Options is the optional "socks5" block of a SOCKS5 inbound.
type SOCKS5Options struct {
	Bind        *SOCKSBindOptions   `json:"bind,omitempty"`
	UDPFragment *UDPFragmentOptions `json:"udp_fragment,omitempty"`
}

// SOCKSBindOptions enables the BIND command (RFC 1928). Omitted: BIND is
// refused with "command not supported" as before.
type SOCKSBindOptions struct {
	Listen  string   `json:"listen,omitempty"`  // literal IP; default: the inbound's listen IP
	Ports   string   `json:"ports"`             // "40000-40099" or "40000": ports BIND may listen on
	Timeout Duration `json:"timeout,omitempty"` // wait for the incoming connection, default 30s

	ip     netip.Addr
	lo, hi int
}

// UDPFragmentOptions bounds the reassembly of fragmented SOCKS5 UDP
// requests of one association.
type UDPFragmentOptions struct {
	Disabled bool     `json:"disabled,omitempty"`  // drop every fragment (FRAG != 0)
	MaxBytes int      `json:"max_bytes,omitempty"` // bytes buffered per association, default 65535
	Timeout  Duration `json:"timeout,omitempty"`   // reassembly timer, default 5s (5s..60s)
}

const (
	defaultBindTimeout = 30 * time.Second
	maxBindPorts       = 4096
)

func (in *Inbound) validateSOCKS5Options(c *Config, i int) error {
	o := in.SOCKS5
	if o == nil {
		return nil
	}
	if in.Protocol != "socks5" {
		return fmt.Errorf("inbound %d: socks5 options require a SOCKS5 inbound", i)
	}
	if f := o.UDPFragment; f != nil {
		if f.MaxBytes == 0 {
			f.MaxBytes = defaultFragmentAssoc
		}
		if f.Timeout == 0 {
			f.Timeout = Duration(defaultFragmentTimeout)
		}
		if f.MaxBytes < 1024 || f.MaxBytes > 65535 || f.Timeout.value() < 5*time.Second || f.Timeout.value() > time.Minute {
			return fmt.Errorf("inbound %d: socks5.udp_fragment.max_bytes must be 1024..65535 and timeout 5s..60s", i)
		}
	}
	b := o.Bind
	if b == nil {
		return nil
	}
	host := b.Listen
	if host == "" {
		host, _, _ = net.SplitHostPort(in.Listen)
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || ip.Zone() != "" {
		return fmt.Errorf("inbound %d: socks5.bind.listen must be a literal IP", i)
	}
	b.ip = ip.Unmap()
	lo, hi, ok := parsePortRange(b.Ports)
	if !ok || hi-lo+1 > maxBindPorts {
		return fmt.Errorf("inbound %d: socks5.bind.ports must be PORT or LOW-HIGH within 1..65535, at most %d ports", i, maxBindPorts)
	}
	b.lo, b.hi = lo, hi
	if b.Timeout == 0 {
		b.Timeout = Duration(defaultBindTimeout)
	}
	if b.Timeout.value() < time.Second || b.Timeout.value() > 10*time.Minute {
		return fmt.Errorf("inbound %d: socks5.bind.timeout must be between 1s and 10m", i)
	}
	// BIND must never take a port Kat itself listens on.
	used := []string{}
	for _, other := range c.Inbounds {
		used = append(used, other.Listen)
	}
	if c.API != nil && c.API.Listen != "" {
		used = append(used, c.API.Listen)
	}
	for _, l := range used {
		h, p, e := net.SplitHostPort(l)
		if e != nil {
			continue
		}
		port, _ := strconv.Atoi(p)
		oip, e := netip.ParseAddr(h)
		if e != nil || port < lo || port > hi {
			continue
		}
		oip = oip.Unmap()
		if oip == b.ip || oip.IsUnspecified() || b.ip.IsUnspecified() {
			return fmt.Errorf("inbound %d: socks5.bind.ports include the configured listener %s", i, l)
		}
	}
	return nil
}

func parsePortRange(s string) (int, int, bool) {
	a, b, found := strings.Cut(s, "-")
	lo, e1 := strconv.Atoi(strings.TrimSpace(a))
	hi := lo
	var e2 error
	if found {
		hi, e2 = strconv.Atoi(strings.TrimSpace(b))
	}
	if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

func (in *Inbound) bindOptions() *SOCKSBindOptions {
	if in.SOCKS5 == nil {
		return nil
	}
	return in.SOCKS5.Bind
}

// fragmentOptions returns the reassembly settings of a SOCKS5 inbound; nil
// when fragments are dropped.
func (in *Inbound) fragmentOptions() *UDPFragmentOptions {
	if in.SOCKS5 != nil && in.SOCKS5.UDPFragment != nil {
		if in.SOCKS5.UDPFragment.Disabled {
			return nil
		}
		return in.SOCKS5.UDPFragment
	}
	return &UDPFragmentOptions{MaxBytes: defaultFragmentAssoc, Timeout: Duration(defaultFragmentTimeout)}
}

// listenBind opens a listening socket on a free port of the BIND range,
// starting at a random port.
func listenBind(o *SOCKSBindOptions) (*net.TCPListener, error) {
	n := o.hi - o.lo + 1
	start := rand.IntN(n)
	var last error
	for i := 0; i < n; i++ {
		port := o.lo + (start+i)%n
		ln, e := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(o.ip, uint16(port))))
		if e == nil {
			return ln, nil
		}
		last = e
	}
	return nil, fmt.Errorf("no free BIND port: %w", last)
}

// SOCKS5 reply codes used by BIND.
const (
	socksSucceeded    = 0
	socksFailure      = 1
	socksNotAllowed   = 2
	socksHostUnreach  = 4
	socksUnsupported  = 7
	socksAddrNotSuppd = 8
)

// serveBind runs one BIND request (RFC 1928): the first reply carries the
// listening address, the second the address of the connecting host; then
// the two connections are relayed. The wait holds one dial slot.
func (s *Server) serveBind(ctx context.Context, c net.Conn, r request, in *Inbound) error {
	o := in.bindOptions()
	reply := func(code byte, a Address) error { return writeAll(c, appendAddress([]byte{5, code, 0}, a, false)) }
	zero := Address{"0.0.0.0", 0}
	// The expected peer (DST.ADDR); unspecified = any host.
	var expect netip.Addr
	if ip, e := netip.ParseAddr(r.Target.Host); e == nil {
		expect = ip.WithZone("").Unmap()
	} else {
		ap, e := s.resolve(ctx, Address{r.Target.Host, 1})
		if e != nil {
			_ = reply(socksHostUnreach, zero)
			return nil
		}
		expect = ap.Addr()
	}
	if expect.IsUnspecified() {
		expect = netip.Addr{}
	}
	if expect.IsValid() && s.cfg.blockedDestination(expect) {
		s.failure(failBlocked, in.Protocol, in.logIndex)
		_ = reply(socksNotAllowed, zero)
		return nil
	}
	if !s.dialSlots.try() {
		s.failure(failDialBudget, in.Protocol, in.logIndex)
		_ = reply(socksFailure, zero)
		return nil
	}
	s.counters.Dials.Add(1)
	held := true
	releaseSlot := func() {
		if held {
			held = false
			s.dialSlots.release()
			s.counters.Dials.Add(-1)
		}
	}
	defer releaseSlot()
	ln, e := listenBind(o)
	if e != nil {
		s.failure(failBindListen, in.Protocol, in.logIndex)
		_ = reply(socksFailure, zero)
		return nil
	}
	defer ln.Close()
	s.bindActive.Add(1)
	defer s.bindActive.Add(-1)
	bound := ln.Addr().(*net.TCPAddr).AddrPort()
	if bound.Addr().IsUnspecified() {
		if la, ok := c.LocalAddr().(*net.TCPAddr); ok {
			bound = netip.AddrPortFrom(la.AddrPort().Addr().Unmap(), bound.Port())
		}
	}
	if e := reply(socksSucceeded, Address{bound.Addr().Unmap().String(), bound.Port()}); e != nil {
		return e
	}
	// The client sends nothing until the second reply: a read returning
	// means it closed (or broke the protocol); stop waiting then.
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		var b [1]byte
		if _, e := c.Read(b[:]); !isTimeout(e) {
			ln.Close()
		}
	}()
	stopWatch := func() {
		_ = c.SetReadDeadline(time.Unix(1, 0))
		<-watchDone
		_ = c.SetReadDeadline(time.Time{})
	}
	_ = ln.SetDeadline(time.Now().Add(o.Timeout.value()))
	var peer *net.TCPConn
	for {
		p, e := ln.AcceptTCP()
		if e != nil {
			stopWatch()
			if isTimeout(e) {
				s.failure(failBindTimeout, in.Protocol, in.logIndex)
				_ = reply(socksFailure, zero)
			}
			return nil
		}
		pa := p.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().WithZone("").Unmap()
		if (expect.IsValid() && pa != expect) || s.cfg.blockedDestination(pa) {
			// Not the announced host, or a source the security options
			// refuse: keep waiting for the right one.
			s.failure(failBlocked, in.Protocol, in.logIndex)
			_ = p.SetLinger(0)
			p.Close()
			continue
		}
		peer = p
		break
	}
	ln.Close()
	releaseSlot()
	stopWatch()
	defer peer.Close()
	from := addrFromNet(peer.RemoteAddr())
	if e := reply(socksSucceeded, from); e != nil {
		return e
	}
	f, fctx := s.newFlow(ctx, "tcp", from)
	f.route(0, []string{"direct"})
	defer f.end("ok")
	return s.relay(fctx, c, peer)
}

func isTimeout(e error) bool {
	var ne net.Error
	return errors.As(e, &ne) && ne.Timeout()
}
