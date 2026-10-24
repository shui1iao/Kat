package group

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// probeFunc measures one member. It returns the latency on success.
type probeFunc func(ctx context.Context, m outbound.Outbound) (time.Duration, error)

var errProbeStatus = errors.New("probe: server error status")

// httpProber issues one HTTP(S) GET to the configured URL through a member.
// Latency is measured from the start of the member dial to the arrival of the
// response headers. Any status < 500 is success (the path works). Redirects
// are not followed and the connection is never reused, so only the configured
// URL is ever contacted, once per member per round.
type httpProber struct {
	url    string
	target outbound.Addr
	tls    *tls.Config // nil: standard verification against system roots
	clk    clock
}

func (p *httpProber) probe(ctx context.Context, m outbound.Outbound) (time.Duration, error) {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Always the configured URL's host:port, through the member.
			return m.DialTCP(ctx, p.target)
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	if p.tls != nil {
		tr.TLSClientConfig = p.tls.Clone()
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Kat-probe")
	start := p.clk.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	lat := p.clk.Now().Sub(start)
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("%w %d", errProbeStatus, resp.StatusCode)
	}
	return lat, nil
}
