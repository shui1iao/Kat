package kernel

import (
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/tlscert"
)

// ---- 0.7.0 server certificates across generations ----
//
// Every Trojan/AnyTLS inbound with a "tls" block gets a dynamic tls.Config
// whose GetCertificate picks, per handshake, among the inbound's certificate
// sources (files, then the ACME certificate) by SNI. Certificates are swapped
// atomically, so established connections (and handshakes in progress) keep
// the certificate they started with:
//   - a reload loads the files again (Validate); a pair that cannot be loaded
//     refuses the whole reload and the running certificates stay;
//   - with tls.watch the files of the current generation are checked by one
//     watcher goroutine; a changed valid pair replaces the certificate, an
//     invalid one is refused with a warning and the previous one stays;
//   - ACME managers are shared by identity across inbounds and reloads and
//     replace their certificate when it is renewed.

type tlsRuntime struct {
	mu       sync.Mutex
	watched  []*watchedPair
	running  bool
	managers map[string]*tlscert.Manager
	lastSums map[string][32]byte // installed content per "cert\x00key"

	alpnMu sync.RWMutex
	alpn   map[string]*tls.Certificate // TLS-ALPN-01 validation certificates

	fbOnce   sync.Once
	fallback *tls.Certificate
}

type watchedPair struct {
	f     *tlscert.FilePair
	every time.Duration
	next  time.Time
}

// tlsPlan is the part of a generation plan installed by commitTLS.
type tlsPlan struct {
	managers map[string]*tlscert.Manager // created by this prepare, not started
	used     map[string]bool             // manager identities of the generation
	watch    map[*tlscert.FilePair]time.Duration
	files    []*tlscert.FilePair // every distinct file pair of the generation
}

func (rt *tlsRuntime) fallbackCert() *tls.Certificate {
	rt.fbOnce.Do(func() {
		if cfg, e := ephemeralTLSConfig(time.Now()); e == nil {
			rt.fallback = &cfg.Certificates[0]
		}
	})
	return rt.fallback
}

func (rt *tlsRuntime) setALPN(domain string, c *tls.Certificate) {
	rt.alpnMu.Lock()
	defer rt.alpnMu.Unlock()
	if rt.alpn == nil {
		rt.alpn = map[string]*tls.Certificate{}
	}
	if c == nil {
		delete(rt.alpn, domain)
	} else {
		rt.alpn[domain] = c
	}
}

func (rt *tlsRuntime) alpnCert(name string) *tls.Certificate {
	rt.alpnMu.RLock()
	defer rt.alpnMu.RUnlock()
	return rt.alpn[strings.ToLower(strings.TrimSuffix(name, "."))]
}

func pairKey(f *tlscert.FilePair) string { return f.CertFile + "\x00" + f.KeyFile }

func (k *core) acmeHooks() tlscert.Hooks {
	return tlscert.Hooks{
		Log: func(level, line string) {
			lv := levelInfo
			switch level {
			case "warn":
				lv = levelWarn
			case "debug":
				lv = levelDebug
			}
			k.notice(lv, line)
		},
		ALPN: k.tlsrt.setALPN,
	}
}

// dynamicTLS returns the per-handshake configuration of an inbound.
func (k *core) dynamicTLS(base *tls.Config, sel *tlscert.Selector) *tls.Config {
	cfg := base.Clone()
	cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c := sel.PickHello(h); c != nil {
			return c, nil
		}
		return nil, errors.New("no certificate available")
	}
	cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		if !slices.Contains(h.SupportedProtos, tlscert.ALPNProto) {
			return nil, nil
		}
		c := k.tlsrt.alpnCert(h.ServerName)
		if c == nil {
			return nil, nil
		}
		return &tls.Config{Certificates: []tls.Certificate{*c}, NextProtos: []string{tlscert.ALPNProto}, MinVersion: tls.VersionTLS12}, nil
	}
	return cfg
}

// prepareTLS builds the dynamic TLS configurations of generation g. Managers
// for new ACME identities are created (stored certificates loaded) but only
// started by commitTLS.
func (g *Server) prepareTLS(p *plan) error {
	k := g.core
	rt := &k.tlsrt
	p.tls = tlsPlan{managers: map[string]*tlscert.Manager{}, used: map[string]bool{}, watch: map[*tlscert.FilePair]time.Duration{}}
	byPath := map[string]*tlscert.FilePair{}
	for i := range g.cfg.Inbounds {
		in := &g.cfg.Inbounds[i]
		st := in.serverTLS
		if st == nil || in.TLS == nil {
			continue
		}
		var sources []tlscert.Source
		for _, f := range st.files {
			if prev := byPath[pairKey(f)]; prev != nil {
				f = prev
			} else {
				byPath[pairKey(f)] = f
				p.tls.files = append(p.tls.files, f)
			}
			sources = append(sources, f)
			if st.watch > 0 {
				if cur, ok := p.tls.watch[f]; !ok || st.watch < cur {
					p.tls.watch[f] = st.watch
				}
			}
		}
		if a := st.acme; a != nil {
			if a.Storage == "" {
				return fmt.Errorf("inbound %d: tls.acme.storage is not set", i)
			}
			id := a.identity()
			rt.mu.Lock()
			m := rt.managers[id]
			rt.mu.Unlock()
			if m == nil {
				m = p.tls.managers[id]
			}
			if m == nil {
				var e error
				if m, e = tlscert.NewManager(a.options(), k.acmeHooks()); e != nil {
					return fmt.Errorf("inbound %d: %w", i, e)
				}
				p.tls.managers[id] = m
			}
			p.tls.used[id] = true
			sources = append(sources, m)
		}
		in.tlsConfig = k.dynamicTLS(st.base, &tlscert.Selector{Sources: sources, Fallback: rt.fallbackCert()})
	}
	return nil
}

// commitTLS installs the certificate sources of generation g.
func (k *core) commitTLS(g *Server, p *plan) {
	rt := &k.tlsrt
	var stop []*tlscert.Manager
	rt.mu.Lock()
	if rt.managers == nil {
		rt.managers = map[string]*tlscert.Manager{}
	}
	for id, m := range p.tls.managers {
		rt.managers[id] = m
		m.Start(k.ctx)
	}
	for id, m := range rt.managers {
		if !p.tls.used[id] {
			delete(rt.managers, id)
			stop = append(stop, m)
		}
	}
	sums := map[string][32]byte{}
	for _, f := range p.tls.files {
		key, sum := pairKey(f), f.Sum()
		if old, ok := rt.lastSums[key]; ok && old != sum {
			k.notice(levelInfo, "kat event=tls_certificate_reloaded source=reload cert="+eventToken(f.CertFile, 256)+certFacts(f.Certificate()))
		}
		sums[key] = sum
	}
	rt.lastSums = sums
	now := time.Now()
	rt.watched = rt.watched[:0:0]
	for f, every := range p.tls.watch {
		rt.watched = append(rt.watched, &watchedPair{f: f, every: every, next: now.Add(every)})
	}
	if len(rt.watched) > 0 && !rt.running {
		rt.running = true
		go k.watchCertificates()
	}
	rt.mu.Unlock()
	for _, m := range stop {
		go m.Stop()
	}
}

func certFacts(c *tls.Certificate) string {
	if c == nil || c.Leaf == nil {
		return ""
	}
	return " not_after=" + c.Leaf.NotAfter.UTC().Format(time.RFC3339) + " serial=" + eventToken(c.Leaf.SerialNumber.Text(16), 64)
}

// watchCertificates checks the watched file pairs of the current generation
// until the server stops.
func (k *core) watchCertificates() {
	rt := &k.tlsrt
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-k.ctx.Done():
			rt.mu.Lock()
			rt.running = false
			rt.mu.Unlock()
			return
		case now := <-t.C:
			rt.mu.Lock()
			var due []*watchedPair
			for _, w := range rt.watched {
				if !now.Before(w.next) {
					w.next = now.Add(w.every)
					due = append(due, w)
				}
			}
			rt.mu.Unlock()
			for _, w := range due {
				res, e := w.f.Check(time.Now())
				switch res {
				case tlscert.Replaced:
					rt.mu.Lock()
					if rt.lastSums != nil {
						rt.lastSums[pairKey(w.f)] = w.f.Sum()
					}
					rt.mu.Unlock()
					k.notice(levelInfo, "kat event=tls_certificate_reloaded source=watch cert="+eventToken(w.f.CertFile, 256)+certFacts(w.f.Certificate()))
				case tlscert.Refused:
					k.notice(levelWarn, "kat event=tls_certificate_reload_failed source=watch cert="+eventToken(w.f.CertFile, 256)+" action=keep_previous reason="+eventToken(e.Error(), 200)+certFacts(w.f.Certificate()))
				}
			}
		}
	}
}
