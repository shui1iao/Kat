package kernel

import (
	"context"
	"crypto/tls"
	"errors"
	XH "github.com/shui1iao/Kat/internal/xhttp"
	"net"
	"reflect"
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

// xhttpCodec is one XHTTP server (HTTP sessions of one listening socket).
type xhttpCodec = *XH.Server

// prepareXHTTP creates the XHTTP servers. On the same listen address an
// identical XHTTP configuration keeps the running server (and its sessions).
func (s *Server) prepareXHTTP(prev *Server) error {
	prevByKey := map[string]*Inbound{}
	if prev != nil {
		for i := range prev.cfg.Inbounds {
			if in := &prev.cfg.Inbounds[i]; in.xhttpServer != nil {
				prevByKey[listenKey(in.Listen)] = in
			}
		}
	}
	for i := range s.cfg.Inbounds {
		in := &s.cfg.Inbounds[i]
		if in.Transport != nil && in.Transport.Type == "xhttp" {
			conf := in.Transport.XHTTP.config(in.Transport, s.cfg.Limits)
			if p := prevByKey[listenKey(in.Listen)]; p != nil && reflect.DeepEqual(p.xhttpConf, conf) {
				in.xhttpServer, in.xhttpConf = p.xhttpServer, conf
				continue
			}
			codec, e := XH.NewServer(conf)
			if e != nil {
				return errors.New("invalid XHTTP server")
			}
			in.xhttpServer, in.xhttpConf = codec, conf
		}
	}
	return nil
}

// The counted raw transport is INSIDE crypto/tls. net/http always receives an
// actual *tls.Conn, so ALPN/H2 dispatch is never hidden by quota wrappers.
type countedHTTPConn struct {
	net.Conn
	s    *core
	once sync.Once
	hand bool
}

func (c *countedHTTPConn) releaseHandshake() {
	c.s.mu.Lock()
	if c.hand {
		c.hand = false
		c.s.counters.Handshakes.Add(-1)
		c.s.handSlots.release()
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
		c.s.guard.releaseConn(addrIP(c.Conn.RemoteAddr()))
		c.s.counters.Active.Add(-1)
		c.s.connSlots.release()
		c.s.wg.Done()
	})
	return e
}

// xhttpListener is the virtual listener of one runner: the accept loop of
// the socket hands it TLS connections.
type xhttpListener struct{ r *xhttpRunner }

func (l xhttpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.r.ready:
		return c, nil
	case <-l.r.closed:
		return nil, net.ErrClosed
	}
}
func (l xhttpListener) Close() error   { l.r.close(); return nil }
func (l xhttpListener) Addr() net.Addr { return &net.TCPAddr{} }

// acceptXHTTP applies the budgets to raw, completes TLS and hands the
// connection to runner r.
func (k *core) acceptXHTTP(raw net.Conn, r *xhttpRunner, cfg *tls.Config, timeout time.Duration) {
	// The source was counted by screen; every refusal here releases it.
	if !k.connSlots.try() {
		raw.Close()
		k.guard.releaseConn(addrIP(raw.RemoteAddr()))
		k.counters.Rejected.Add(1)
		return
	}
	if !k.handSlots.try() {
		k.connSlots.release()
		raw.Close()
		k.guard.releaseConn(addrIP(raw.RemoteAddr()))
		k.counters.Rejected.Add(1)
		return
	}
	c := &countedHTTPConn{Conn: raw, s: k, hand: true}
	k.mu.Lock()
	if k.closing {
		k.mu.Unlock()
		k.handSlots.release()
		k.connSlots.release()
		raw.Close()
		k.guard.releaseConn(addrIP(raw.RemoteAddr()))
		return
	}
	k.wg.Add(1)
	k.active[c] = &acceptedState{}
	k.mu.Unlock()
	k.counters.Active.Add(1)
	k.counters.Accepted.Add(1)
	k.counters.Handshakes.Add(1)
	go func() {
		c.SetDeadline(time.Now().Add(timeout))
		tc := tls.Server(c, cfg)
		if tc.HandshakeContext(k.ctx) != nil {
			tc.Close()
			return
		}
		c.releaseHandshake()
		tc.SetDeadline(time.Time{})
		select {
		case r.ready <- tc:
		case <-r.closed:
			tc.Close()
		case <-k.ctx.Done():
			tc.Close()
		}
	}()
}

// runXHTTP serves runner r until it is closed. Every stream uses the
// generation the runner is bound to when the stream starts.
func (k *core) runXHTTP(r *xhttpRunner) {
	defer k.accepts.Done()
	defer r.close()
	_ = r.codec.Serve(k.ctx, xhttpListener{r}, func(ctx context.Context, st *XH.Stream, meta XH.Metadata) error {
		s, idx := k.refRunner(r)
		if s == nil {
			return errors.New("configuration released")
		}
		defer s.unref()
		in := s.cfg.Inbounds[idx]
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
		if !s.logicalSlots.try() {
			return errors.New("logical quota")
		}
		s.logical.Add(1)
		defer func() { s.logicalSlots.release(); s.logical.Add(-1) }()
		if !s.handSlots.try() {
			return errors.New("handshake quota")
		}
		s.counters.Handshakes.Add(1)
		// SessionID/RemoteIP are HTTP pairing metadata, never user credentials.
		conn := &boundedStream{Conn: streamAddrConn{remote: meta.RemoteAddr}, rw: st, deadline: st}
		return s.vlessRequest(ctx, conn, nil, in, func() { s.handSlots.release(); s.counters.Handshakes.Add(-1) }, false)
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
	mUp, mDown := meters(ctx)
	go func() {
		e := s.copyM(out, c, mUp)
		if e == nil {
			e = closeWrite(out)
		}
		done <- result{true, e}
	}()
	go func() { done <- result{false, s.copyM(c, out, mDown)} }()
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
