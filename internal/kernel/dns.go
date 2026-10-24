package kernel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type dnsCacheEntry struct {
	ips     []netip.Addr
	expires time.Time
}
type internalDNS struct {
	ep        dnsEndpoint
	capacity  int
	slots     chan struct{}
	mu        sync.Mutex
	cache     map[string]dnsCacheEntry
	now       func() time.Time
	bootstrap func(context.Context, string, string) ([]netip.Addr, error)
	transport *http.Transport
	client    *http.Client
}

func newInternalDNS(o *DNSOptions) (*internalDNS, error) {
	var ep dnsEndpoint
	var e error
	if o == nil {
		ep.scheme = "system"
	} else {
		ep, e = parseDNS(o.Server)
		if e != nil {
			return nil, e
		}
	}
	r := &internalDNS{ep: ep, capacity: 256, slots: make(chan struct{}, 64), cache: make(map[string]dnsCacheEntry), now: time.Now, bootstrap: net.DefaultResolver.LookupNetIP}
	if ep.scheme == "system" {
		r.capacity = 0
	}
	if o != nil && o.CacheEntries != nil {
		r.capacity = *o.CacheEntries
	}
	if ep.scheme == "https" {
		// ProxyFromEnvironment is deliberately not used: this is a single configured upstream.
		r.transport = &http.Transport{MaxConnsPerHost: 64, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 8192, DisableCompression: true, ForceAttemptHTTP2: false}
		r.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return r.connect(ctx, "tcp") }
		r.client = &http.Client{Transport: r.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DNS redirect rejected") }}
	}
	return r, nil
}
func (r *internalDNS) close() {
	if r != nil && r.transport != nil {
		r.transport.CloseIdleConnections()
	}
}
func (r *internalDNS) cached(name string) ([]netip.Addr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[name]
	if !ok {
		return nil, false
	}
	if !e.expires.After(r.now()) {
		delete(r.cache, name)
		return nil, false
	}
	return append([]netip.Addr(nil), e.ips...), true
}
func (r *internalDNS) cachePut(name string, ips []netip.Addr, ttl time.Duration) {
	if r.capacity == 0 || ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var oldest string
	var earliest time.Time
	for k, e := range r.cache {
		if !e.expires.After(now) {
			delete(r.cache, k)
			continue
		}
		if earliest.IsZero() || e.expires.Before(earliest) {
			oldest, earliest = k, e.expires
		}
	}
	if _, ok := r.cache[name]; !ok && len(r.cache) >= r.capacity {
		delete(r.cache, oldest)
	}
	r.cache[name] = dnsCacheEntry{append([]netip.Addr(nil), ips...), now.Add(ttl)}
}
func (r *internalDNS) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	name, e := dnsName(name)
	if e != nil {
		return nil, errDNS
	}
	if r.ep.scheme == "system" {
		return r.bootstrap(ctx, "ip", name)
	}
	if r.capacity > 0 {
		if ips, ok := r.cached(name); ok {
			return ips, nil
		}
	}
	// Acquire BEFORE spawning the two family workers. No unbounded per-query workers.
	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-r.slots }()
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errDNS
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, ctx.Err()
	}
	qctx, cancel := context.WithTimeout(ctx, remaining/2)
	defer cancel()
	type result struct {
		answer dnsAnswer
		err    error
	}
	var results [2]result
	var wg sync.WaitGroup
	for i, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		wg.Add(1)
		go func(i int, typ dnsmessage.Type) {
			defer wg.Done()
			results[i].answer, results[i].err = r.query(qctx, name, typ)
		}(i, typ)
	}
	wg.Wait()
	var ips []netip.Addr
	seen := map[netip.Addr]bool{}
	complete := true
	ttl := 300 * time.Second
	for _, v := range results {
		if v.err != nil {
			complete = false
			continue
		}
		if len(v.answer.ips) > 0 && v.answer.ttl < ttl {
			ttl = v.answer.ttl
		}
		for _, ip := range v.answer.ips {
			ip = ip.Unmap()
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
				if len(ips) > maxDNSAddresses {
					return nil, errDNS
				}
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(ips) == 0 {
		return nil, errDNS
	}
	if complete {
		r.cachePut(name, ips, ttl)
	}
	return ips, nil
}
func (r *internalDNS) connect(ctx context.Context, network string) (net.Conn, error) {
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(r.ep.host); e == nil {
		ips = []netip.Addr{ip}
	} else {
		var e error
		ips, e = r.bootstrap(ctx, "ip", r.ep.host)
		if e != nil {
			return nil, errDNS
		}
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	for _, ip := range ips {
		c, e := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), r.ep.port))
		if e == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errDNS
}
func (r *internalDNS) query(ctx context.Context, name string, typ dnsmessage.Type) (dnsAnswer, error) {
	wire, q, e := dnsQuestion(name, typ)
	if e != nil {
		return dnsAnswer{}, errDNS
	}
	id := binary.BigEndian.Uint16(wire[:2])
	var answer []byte
	switch r.ep.scheme {
	case "udp", "tcp":
		answer, e = r.exchange(ctx, r.ep.scheme, wire)
	case "https":
		req, er := http.NewRequestWithContext(ctx, http.MethodPost, r.ep.url, bytes.NewReader(wire))
		if er != nil {
			return dnsAnswer{}, errDNS
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, er := r.client.Do(req)
		if er != nil {
			return dnsAnswer{}, errDNS
		}
		defer resp.Body.Close()
		media, _, er := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if er != nil || media != "application/dns-message" || resp.StatusCode != http.StatusOK || resp.ContentLength > maxDNSMessage {
			return dnsAnswer{}, errDNS
		}
		answer, e = io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	default:
		return dnsAnswer{}, errDNS
	}
	if e != nil || len(answer) > maxDNSMessage {
		return dnsAnswer{}, errDNS
	}
	a, e := parseDNSAnswer(answer, id, q)
	if e != nil {
		return dnsAnswer{}, e
	}
	if a.truncated {
		if r.ep.scheme != "udp" {
			return dnsAnswer{}, errDNS
		}
		answer, e = r.exchange(ctx, "tcp", wire)
		if e != nil {
			return dnsAnswer{}, errDNS
		}
		a, e = parseDNSAnswer(answer, id, q)
		if e != nil || a.truncated {
			return dnsAnswer{}, errDNS
		}
	}
	return a, nil
}
func (r *internalDNS) exchange(ctx context.Context, network string, wire []byte) ([]byte, error) {
	c, e := r.connect(ctx, network)
	if e != nil {
		return nil, errDNS
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if network == "tcp" {
		b := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
		b = append(b, wire...)
		if e = writeAll(c, b); e != nil {
			return nil, errDNS
		}
		var size [2]byte
		if _, e = io.ReadFull(c, size[:]); e != nil {
			return nil, errDNS
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 12 {
			return nil, errDNS
		}
		b = make([]byte, n)
		_, e = io.ReadFull(c, b)
		return b, e
	}
	if _, e = c.Write(wire); e != nil {
		return nil, errDNS
	}
	b := make([]byte, maxDNSMessage+1)
	n, e := c.Read(b)
	if e != nil || n > maxDNSMessage {
		return nil, errDNS
	}
	return b[:n], nil
}
