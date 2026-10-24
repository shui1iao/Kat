// Package direct is Kat's built-in first-hop dialer. It does not consult
// routing rules: callers (kernel, proxy outbounds) have already decided that
// the destination is to be reached directly.
package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Options configures the direct dialer. All fields may be zero.
type Options struct {
	// Resolve resolves a domain name (kernel-injected, uses Kat's dns settings).
	// nil uses the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// BindIPv4/BindIPv6 are the local UDP bind addresses (udp_bind_ipv4/ipv6).
	BindIPv4, BindIPv6 netip.Addr
	// Timeout bounds one DialTCP (resolution plus all candidate attempts) and
	// one WriteTo domain resolution. Zero means only the caller's ctx applies
	// (resolution inside WriteTo then uses a 5s bound).
	Timeout time.Duration
}

// Outbound implements outbound.Outbound for direct connections.
type Outbound struct{ o Options }

var _ outbound.Outbound = (*Outbound)(nil)

// New returns a direct outbound. It performs no I/O.
func New(o Options) *Outbound { return &Outbound{o: o} }

func (d *Outbound) Name() string { return "direct" }
func (d *Outbound) Type() string { return "direct" }
func (d *Outbound) UDP() bool    { return true }
func (d *Outbound) Close() error { return nil }

var (
	errZeroPort   = errors.New("direct: zero destination port")
	errNoAddress  = errors.New("direct: no usable address")
	errDialFailed = errors.New("direct: all candidate addresses failed")
)

func (d *Outbound) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return nil, errNoAddress
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	var ips []netip.Addr
	var e error
	if d.o.Resolve != nil {
		ips, e = d.o.Resolve(ctx, host)
	} else {
		ips, e = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	if e != nil {
		return nil, e
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.IsValid() && ip.Zone() == "" {
			out = append(out, ip.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, errNoAddress
	}
	return out, nil
}

// DialTCP resolves dst (when it is a name) and dials the candidates in order.
func (d *Outbound) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	if dst.Port == 0 {
		return nil, errZeroPort
	}
	if d.o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.o.Timeout)
		defer cancel()
	}
	ips, e := d.resolve(ctx, dst.Host)
	if e != nil {
		return nil, e
	}
	var last error
	for _, ip := range ips {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", netip.AddrPortFrom(ip, dst.Port).String())
		if e == nil {
			return c, nil
		}
		last = e
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if last == nil {
		last = errDialFailed
	}
	return nil, last
}

// ListenPacket returns a PacketConn that can send to IPv4 and IPv6 targets.
// Only datagrams from an exact IP:port previously written to are delivered.
func (d *Outbound) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	p := &packetConn{d: d, sent: map[netip.AddrPort]struct{}{}, names: map[string]netip.Addr{}, in: make(chan datagram, inboxSize), closed: make(chan struct{})}
	bind4 := d.o.BindIPv4
	if !bind4.IsValid() {
		bind4 = netip.IPv4Unspecified()
	}
	bind6 := d.o.BindIPv6
	if !bind6.IsValid() {
		bind6 = netip.IPv6Unspecified()
	}
	var e4, e6 error
	p.v4, e4 = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(bind4.Unmap(), 0)))
	p.v6, e6 = net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(bind6, 0)))
	// An explicitly configured bind address must work; a missing default
	// family (e.g. IPv6 disabled) only removes that family.
	if e4 != nil && (d.o.BindIPv4.IsValid() || e6 != nil) || e6 != nil && d.o.BindIPv6.IsValid() {
		if p.v4 != nil {
			p.v4.Close()
		}
		if p.v6 != nil {
			p.v6.Close()
		}
		if e4 != nil {
			return nil, e4
		}
		return nil, e6
	}
	for _, s := range []*net.UDPConn{p.v4, p.v6} {
		if s != nil {
			p.wg.Add(1)
			go p.reader(s)
		}
	}
	return p, nil
}

const (
	inboxSize   = 64
	maxSent     = 4096
	maxNames    = 64
	maxDatagram = 65535
)

type datagram struct {
	b   []byte
	src netip.AddrPort
}

type packetConn struct {
	d      *Outbound
	v4, v6 *net.UDPConn

	mu        sync.Mutex
	sent      map[netip.AddrPort]struct{}
	order     []netip.AddrPort
	names     map[string]netip.Addr
	rdeadline time.Time
	rchanged  chan struct{}

	in        chan datagram
	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func (p *packetConn) allowed(src netip.AddrPort) bool {
	p.mu.Lock()
	_, ok := p.sent[src]
	p.mu.Unlock()
	return ok
}

func (p *packetConn) reader(s *net.UDPConn) {
	defer p.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, src, e := s.ReadFromUDPAddrPort(buf)
		if e != nil {
			var ne net.Error
			if errors.As(e, &ne) && ne.Timeout() {
				continue
			}
			select {
			case <-p.closed:
				return
			default:
			}
			// Transient errors (e.g. ICMP-induced) must not end the session.
			if errors.Is(e, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if !p.allowed(src) {
			continue
		}
		b := append([]byte(nil), buf[:n]...)
		select {
		case p.in <- datagram{b, src}:
		case <-p.closed:
			return
		default:
			// Inbox full: drop, like a full socket buffer.
		}
	}
}

func (p *packetConn) ReadFrom(b []byte) (int, outbound.Addr, error) {
	for {
		p.mu.Lock()
		deadline := p.rdeadline
		if p.rchanged == nil {
			p.rchanged = make(chan struct{})
		}
		changed := p.rchanged
		p.mu.Unlock()
		var timer <-chan time.Time
		var t *time.Timer
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, outbound.Addr{}, os.ErrDeadlineExceeded
			}
			t = time.NewTimer(d)
			timer = t.C
		}
		select {
		case <-p.closed:
			stopTimer(t)
			return 0, outbound.Addr{}, net.ErrClosed
		case g := <-p.in:
			stopTimer(t)
			n := copy(b, g.b)
			return n, outbound.Addr{Host: g.src.Addr().String(), Port: g.src.Port()}, nil
		case <-timer:
			return 0, outbound.Addr{}, os.ErrDeadlineExceeded
		case <-changed:
			stopTimer(t)
		}
	}
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

func (p *packetConn) target(dst outbound.Addr) (netip.AddrPort, error) {
	if dst.Port == 0 {
		return netip.AddrPort{}, errZeroPort
	}
	if ip, ok := dst.IP(); ok {
		return netip.AddrPortFrom(ip, dst.Port), nil
	}
	p.mu.Lock()
	ip, ok := p.names[dst.Host]
	p.mu.Unlock()
	if ok {
		return netip.AddrPortFrom(ip, dst.Port), nil
	}
	timeout := p.d.o.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		select {
		case <-p.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	ips, e := p.d.resolve(ctx, dst.Host)
	if e != nil {
		return netip.AddrPort{}, e
	}
	for _, ip := range ips {
		if ip.Is4() && p.v4 != nil || ip.Is6() && p.v6 != nil {
			p.mu.Lock()
			if len(p.names) >= maxNames {
				clear(p.names)
			}
			p.names[dst.Host] = ip
			p.mu.Unlock()
			return netip.AddrPortFrom(ip, dst.Port), nil
		}
	}
	return netip.AddrPort{}, errNoAddress
}

func (p *packetConn) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	if len(b) > maxDatagram {
		return 0, errors.New("direct: datagram too large")
	}
	t, e := p.target(dst)
	if e != nil {
		return 0, e
	}
	s := p.v4
	if t.Addr().Is6() {
		s = p.v6
	}
	if s == nil {
		return 0, errNoAddress
	}
	p.mu.Lock()
	if _, ok := p.sent[t]; !ok {
		if len(p.order) >= maxSent {
			delete(p.sent, p.order[0])
			p.order = p.order[1:]
		}
		p.sent[t] = struct{}{}
		p.order = append(p.order, t)
	}
	p.mu.Unlock()
	return s.WriteToUDPAddrPort(b, t)
}

func (p *packetConn) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		if p.v4 != nil {
			p.v4.Close()
		}
		if p.v6 != nil {
			p.v6.Close()
		}
	})
	p.wg.Wait()
	return nil
}

func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.rdeadline = t
	if p.rchanged != nil {
		close(p.rchanged)
		p.rchanged = nil
	}
	p.mu.Unlock()
	return nil
}

func (p *packetConn) SetWriteDeadline(t time.Time) error {
	for _, s := range []*net.UDPConn{p.v4, p.v6} {
		if s != nil {
			if e := s.SetWriteDeadline(t); e != nil {
				return e
			}
		}
	}
	return nil
}
