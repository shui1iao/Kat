package group

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// observer watches the first exchange of a TCP connection and reports exactly
// once:
//   - success when the first byte is read (with the time from the first Write
//     to that byte, when something was written first);
//   - failure when, after data was written and before any byte was read, a
//     Read returns EOF/error or a Write fails (caller deadlines and the
//     caller's own Close are not failures);
//   - failure when noReply > 0 and nothing was read within noReply after the
//     first Write.
//
// A connection that is closed by its owner before any of these happens
// reports nothing. Observation never changes what the caller sees.
type observer struct {
	clk     clock
	noReply time.Duration
	report  func(ok bool, ttfb time.Duration, hasTTFB bool)

	done atomic.Bool // fast path once reported or closed

	mu      sync.Mutex
	wrote   bool
	wroteAt time.Time
	closed  bool
	stop    func() bool
}

func (o *observer) beforeWrite(n int) {
	if n == 0 || o.done.Load() {
		return
	}
	o.mu.Lock()
	if !o.wrote && !o.closed && !o.done.Load() {
		o.wrote, o.wroteAt = true, o.clk.Now()
		if o.noReply > 0 {
			o.stop = o.clk.AfterFunc(o.noReply, func() { o.finish(false) })
		}
	}
	o.mu.Unlock()
}

func (o *observer) afterWrite(err error) {
	if err != nil && !o.done.Load() && !isDeadline(err) {
		o.finish(false)
	}
}

func (o *observer) afterRead(n int, err error) {
	if o.done.Load() {
		return
	}
	if n > 0 {
		o.finish(true)
		return
	}
	if err != nil && !isDeadline(err) {
		o.mu.Lock()
		wrote := o.wrote
		o.mu.Unlock()
		if wrote {
			o.finish(false)
		}
	}
}

func (o *observer) finish(ok bool) {
	o.mu.Lock()
	if o.closed || o.done.Load() {
		o.mu.Unlock()
		return
	}
	o.done.Store(true)
	if o.stop != nil {
		o.stop()
	}
	has, ttfb := o.wrote, time.Duration(0)
	if has {
		ttfb = o.clk.Now().Sub(o.wroteAt)
	}
	o.mu.Unlock()
	o.report(ok, ttfb, ok && has)
}

func (o *observer) close() {
	o.mu.Lock()
	o.closed = true
	if o.stop != nil {
		o.stop()
	}
	o.done.Store(true)
	o.mu.Unlock()
}

func isDeadline(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type closeWriter interface{ CloseWrite() error }

// obsConn is a transparent wrapper: every call goes to the inner conn
// unchanged; the observer only looks at sizes and errors.
type obsConn struct {
	net.Conn
	o *observer
}

func (c *obsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.o.afterRead(n, err)
	return n, err
}

func (c *obsConn) Write(p []byte) (int, error) {
	c.o.beforeWrite(len(p))
	n, err := c.Conn.Write(p)
	c.o.afterWrite(err)
	return n, err
}

func (c *obsConn) Close() error {
	c.o.close()
	return c.Conn.Close()
}

// obsConnCW is used when the inner conn supports half-close, so that callers
// detecting CloseWrite by type assertion see the same capability.
type obsConnCW struct{ *obsConn }

func (c obsConnCW) CloseWrite() error { return c.Conn.(closeWriter).CloseWrite() }

func wrapConn(c net.Conn, o *observer) net.Conn {
	oc := &obsConn{Conn: c, o: o}
	if _, ok := c.(closeWriter); ok {
		return obsConnCW{oc}
	}
	return oc
}

// obsPacket reports a failure when a datagram was sent and no datagram came
// back within noReply. After such a failure no further failure is reported
// until a reply arrives (one failure per silent period). The first reply and
// the first reply after a silent period are reported as success.
type obsPacket struct {
	outbound.PacketConn
	clk     clock
	noReply time.Duration
	report  func(ok bool)

	mu      sync.Mutex
	armed   bool
	silent  bool
	replied bool
	closed  bool
	gen     uint64
	stop    func() bool
}

func (p *obsPacket) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	n, err := p.PacketConn.WriteTo(b, dst)
	if err == nil {
		p.mu.Lock()
		if !p.armed && !p.silent && !p.closed {
			p.armed = true
			p.gen++
			gen := p.gen
			p.stop = p.clk.AfterFunc(p.noReply, func() { p.expire(gen) })
		}
		p.mu.Unlock()
	}
	return n, err
}

func (p *obsPacket) ReadFrom(b []byte) (int, outbound.Addr, error) {
	n, src, err := p.PacketConn.ReadFrom(b)
	if err == nil {
		p.mu.Lock()
		notify := !p.closed && (!p.replied || p.silent)
		p.replied, p.silent = true, false
		if p.armed {
			p.armed = false
			p.stop()
		}
		p.mu.Unlock()
		if notify {
			p.report(true)
		}
	}
	return n, src, err
}

func (p *obsPacket) expire(gen uint64) {
	p.mu.Lock()
	fire := p.armed && !p.closed && gen == p.gen
	if !fire {
		p.mu.Unlock()
		return
	}
	p.armed, p.silent = false, true
	p.mu.Unlock()
	p.report(false)
}

func (p *obsPacket) Close() error {
	p.mu.Lock()
	p.closed = true
	if p.armed {
		p.armed = false
		p.stop()
	}
	p.mu.Unlock()
	return p.PacketConn.Close()
}
