package kernel

import (
	"context"
	"crypto/tls"
	"errors"
	XH "github.com/shui1iao/Kat/internal/xhttp"
	"net"
	"sync"
	"time"
)

type XHTTPOptions struct {
	ALPN                   []string `json:"alpn,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	NoSSEHeader            bool     `json:"no_sse_header,omitempty"`
	MaxRequests            int      `json:"max_requests,omitempty"`
	MaxSessions            int      `json:"max_sessions,omitempty"`
	MaxUnpaired            int      `json:"max_unpaired,omitempty"`
	MaxRetired             int      `json:"max_retired,omitempty"`
	MaxPacketBytes         int      `json:"max_packet_bytes,omitempty"`
	MaxBufferedPackets     int      `json:"max_buffered_packets,omitempty"`
	MaxBufferedBytes       int      `json:"max_buffered_bytes,omitempty"`
	MaxGlobalBufferedBytes int      `json:"max_global_buffered_bytes,omitempty"`
	MaxUploads             int      `json:"max_uploads,omitempty"`
	MaxUploadBytes         int64    `json:"max_upload_bytes,omitempty"`
	PairTimeout            Duration `json:"pair_timeout,omitempty"`
	IOTimeout              Duration `json:"io_timeout,omitempty"`
	RetiredTTL             Duration `json:"retired_ttl,omitempty"`
}

func (o *XHTTPOptions) config(v *VTransportOptions, l Limits) XH.Config {
	return XH.Config{Path: v.Path, Host: v.Host, Mode: o.Mode, NoSSEHeader: o.NoSSEHeader, MaxConnections: l.Connections, MaxRequests: o.MaxRequests, MaxSessions: o.MaxSessions, MaxUnpaired: o.MaxUnpaired, MaxHandlers: v.MaxStreams, MaxRetired: o.MaxRetired, MaxPacketBytes: o.MaxPacketBytes, MaxBufferedPackets: o.MaxBufferedPackets, MaxBufferedBytes: o.MaxBufferedBytes, MaxGlobalBufferedBytes: o.MaxGlobalBufferedBytes, MaxUploads: o.MaxUploads, MaxUploadBytes: o.MaxUploadBytes, HeaderTimeout: l.HandshakeTimeout.value(), IdleTimeout: 30 * time.Second, PairTimeout: o.PairTimeout.value(), IOTimeout: o.IOTimeout.value(), ShutdownTimeout: l.DrainTimeout.value(), RetiredTTL: o.RetiredTTL.value()}
}
func (o *XHTTPOptions) validate(v *VTransportOptions, l Limits) error {
	if len(o.ALPN) > 2 {
		return errors.New("XHTTP ALPN supports only h2/http/1.1")
	}
	seen := map[string]bool{}
	for _, p := range o.ALPN {
		if (p != "h2" && p != "http/1.1") || seen[p] {
			return errors.New("invalid XHTTP ALPN")
		}
		seen[p] = true
	}
	for _, p := range []*int{&o.MaxRequests, &o.MaxSessions, &o.MaxUnpaired, &o.MaxRetired, &o.MaxPacketBytes, &o.MaxBufferedPackets, &o.MaxBufferedBytes, &o.MaxGlobalBufferedBytes, &o.MaxUploads} {
		if *p < 0 || *p > 1<<28 {
			return errors.New("invalid XHTTP capacity")
		}
	}
	for _, d := range []Duration{o.PairTimeout, o.IOTimeout, o.RetiredTTL} {
		if d < 0 || d.value() > 24*time.Hour {
			return errors.New("invalid XHTTP timeout")
		}
	}
	if _, e := XH.NewServer(o.config(v, l)); e != nil {
		return errors.New("invalid XHTTP config")
	}
	return nil
}
func (s *Server) prepareXHTTP() error {
	for i := range s.cfg.Inbounds {
		in := &s.cfg.Inbounds[i]
		if in.Transport != nil && in.Transport.Type == "xhttp" {
			codec, e := XH.NewServer(in.Transport.XHTTP.config(in.Transport, s.cfg.Limits))
			if e != nil {
				return errors.New("invalid XHTTP server")
			}
			in.xhttpServer = codec
		}
	}
	return nil
}

// The counted raw transport is INSIDE crypto/tls. net/http always receives an
// actual *tls.Conn, so ALPN/H2 dispatch is never hidden by quota wrappers.
type countedHTTPConn struct {
	net.Conn
	s    *Server
	once sync.Once
	hand bool
}

func (c *countedHTTPConn) releaseHandshake() {
	c.s.mu.Lock()
	if c.hand {
		c.hand = false
		c.s.counters.Handshakes.Add(-1)
		<-c.s.handSlots
	}
	c.s.mu.Unlock()
}
func (c *countedHTTPConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() {
		c.releaseHandshake()
		c.s.mu.Lock()
		delete(c.s.active, c)
		c.s.mu.Unlock()
		c.s.counters.Active.Add(-1)
		<-c.s.connSlots
		c.s.wg.Done()
	})
	return e
}

type xhttpTLSListener struct {
	net.Listener
	s        *Server
	cfg      *tls.Config
	ready    chan net.Conn
	closed   chan struct{}
	once     sync.Once
	pumpDone chan struct{}
}

func (l *xhttpTLSListener) Close() error {
	e := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return e
}
func (l *xhttpTLSListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		if c == nil {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *xhttpTLSListener) pump() {
	defer close(l.pumpDone)
	defer l.Close()
	for {
		raw, e := l.Listener.Accept()
		if e != nil {
			l.Close()
			return
		}
		s := l.s
		if !acquire(s.connSlots) {
			raw.Close()
			s.counters.Rejected.Add(1)
			continue
		}
		if !acquire(s.handSlots) {
			<-s.connSlots
			raw.Close()
			s.counters.Rejected.Add(1)
			continue
		}
		c := &countedHTTPConn{Conn: raw, s: s, hand: true}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			<-s.handSlots
			<-s.connSlots
			raw.Close()
			return
		}
		s.wg.Add(1)
		s.active[c] = &acceptedState{}
		s.mu.Unlock()
		s.counters.Active.Add(1)
		s.counters.Accepted.Add(1)
		s.counters.Handshakes.Add(1)
		go func() {
			c.SetDeadline(time.Now().Add(s.cfg.Limits.HandshakeTimeout.value()))
			tc := tls.Server(c, l.cfg)
			if tc.HandshakeContext(s.ctx) != nil {
				tc.Close()
				return
			}
			c.releaseHandshake()
			tc.SetDeadline(time.Time{})
			select {
			case l.ready <- tc:
			case <-l.closed:
				tc.Close()
			case <-s.ctx.Done():
				tc.Close()
			}
		}()
	}
}
func (s *Server) serveXHTTP(ln net.Listener, in Inbound) {
	defer s.accepts.Done()
	l := &xhttpTLSListener{Listener: ln, s: s, cfg: in.tlsConfig, ready: make(chan net.Conn), closed: make(chan struct{}), pumpDone: make(chan struct{})}
	go l.pump()
	defer func() { l.Close(); <-l.pumpDone }()
	_ = in.xhttpServer.Serve(s.ctx, l, func(ctx context.Context, st *XH.Stream, meta XH.Metadata) error {
		if meta.HTTPMajor == 2 {
			s.xhttpH2.Add(1)
		} else {
			s.xhttpH1.Add(1)
		}
		defer func() {
			switch st.Mode() {
			case XH.PacketUp:
				s.xhttpPacket.Add(1)
			case XH.StreamUp:
				s.xhttpStreamUp.Add(1)
			case XH.StreamOne:
				s.xhttpStreamOne.Add(1)
			}
		}()
		if !acquire(s.logicalSlots) {
			return errors.New("logical quota")
		}
		s.logical.Add(1)
		defer func() { <-s.logicalSlots; s.logical.Add(-1) }()
		if !acquire(s.handSlots) {
			return errors.New("handshake quota")
		}
		s.counters.Handshakes.Add(1)
		// SessionID/RemoteIP are HTTP pairing metadata, never user credentials.
		conn := &boundedStream{Conn: streamAddrConn{remote: meta.RemoteAddr}, rw: st, deadline: st}
		return s.vlessRequest(ctx, conn, nil, in, func() { <-s.handSlots; s.counters.Handshakes.Add(-1) }, false)
	})
}

// Only addresses are borrowed from transport metadata. All I/O/deadlines are
// explicitly overridden by boundedStream; no raw socket bypass exists.
type streamAddrConn struct {
	net.Conn
	remote string
}

func (c streamAddrConn) RemoteAddr() net.Addr { a, _ := net.ResolveTCPAddr("tcp", c.remote); return a }
func (c streamAddrConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }

// XHTTP has no response half-close, but streaming upload EOF MUST preserve the
// download tail. Close target write after input EOF, join reverse before Close.
func (s *Server) relayXHTTP(ctx context.Context, c, out net.Conn) {
	type result struct {
		upload bool
		e      error
	}
	done := make(chan result, 2)
	go func() {
		e := s.copy(out, c)
		if e == nil {
			e = closeWrite(out)
		}
		done <- result{true, e}
	}()
	go func() { done <- result{false, s.copy(c, out)} }()
	var first result
	select {
	case first = <-done:
	case <-ctx.Done():
		c.Close()
		out.Close()
		<-done
		<-done
		return
	}
	if !first.upload || first.e != nil {
		c.Close()
		out.Close()
	} else {
		end := time.Now().Add(s.cfg.Limits.DrainTimeout.value())
		c.SetWriteDeadline(end)
		out.SetReadDeadline(end)
	}
	select {
	case <-done:
	case <-ctx.Done():
		c.Close()
		out.Close()
		<-done
	}
}
