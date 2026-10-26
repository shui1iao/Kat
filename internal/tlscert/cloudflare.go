package tlscert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DNSProvider creates and removes the TXT record of a DNS-01 challenge.
type DNSProvider interface {
	// Present creates a TXT record fqdn (no trailing dot) with value and
	// returns an identifier for CleanUp.
	Present(ctx context.Context, fqdn, value string) (string, error)
	CleanUp(ctx context.Context, fqdn, id string) error
}

// DefaultCloudflareAPI is the Cloudflare API v4 base URL.
const DefaultCloudflareAPI = "https://api.cloudflare.com/client/v4"

// Cloudflare is a DNS-01 provider using a scoped API token (Zone:DNS:Edit on
// the zone; Zone:Read as well when ZoneID is not given). The token is only
// sent in the Authorization header and never logged.
type Cloudflare struct {
	Token  string
	ZoneID string // optional: skips the zone lookup
	APIURL string // default DefaultCloudflareAPI
	TTL    int    // default 120
	HTTP   *http.Client
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Cloudflare) do(ctx context.Context, method, path string, body any, out any) error {
	base := c.APIURL
	if base == "" {
		base = DefaultCloudflareAPI
	}
	var rd io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		rd = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, rd)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	res, e := hc.Do(req)
	if e != nil {
		return fmt.Errorf("cloudflare: %s request failed", method)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var r cfResponse
	if json.Unmarshal(b, &r) != nil {
		return fmt.Errorf("cloudflare: HTTP %d with an unreadable body", res.StatusCode)
	}
	if !r.Success || res.StatusCode/100 != 2 {
		msg := fmt.Sprintf("cloudflare: HTTP %d", res.StatusCode)
		for _, er := range r.Errors {
			msg += fmt.Sprintf(" [%d %s]", er.Code, er.Message)
		}
		return errors.New(msg)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (c *Cloudflare) zone(ctx context.Context, fqdn string) (string, error) {
	if c.ZoneID != "" {
		return c.ZoneID, nil
	}
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := 0; i+1 < len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		var zones []struct {
			ID string `json:"id"`
		}
		if e := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), nil, &zones); e != nil {
			return "", e
		}
		if len(zones) > 0 && zones[0].ID != "" {
			return zones[0].ID, nil
		}
	}
	return "", errors.New("cloudflare: zone not found (set dns.zone_id or grant Zone:Read)")
}

// Present creates the TXT record; the returned id is "zoneID/recordID".
func (c *Cloudflare) Present(ctx context.Context, fqdn, value string) (string, error) {
	zone, e := c.zone(ctx, fqdn)
	if e != nil {
		return "", e
	}
	ttl := c.TTL
	if ttl == 0 {
		ttl = 120
	}
	var rec struct {
		ID string `json:"id"`
	}
	body := map[string]any{"type": "TXT", "name": strings.TrimSuffix(fqdn, "."), "content": value, "ttl": ttl}
	if e := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone)+"/dns_records", body, &rec); e != nil {
		return "", e
	}
	if rec.ID == "" {
		return "", errors.New("cloudflare: record id missing")
	}
	return zone + "/" + rec.ID, nil
}

// CleanUp deletes the record created by Present.
func (c *Cloudflare) CleanUp(ctx context.Context, _ string, id string) error {
	zone, rec, ok := strings.Cut(id, "/")
	if !ok {
		return errors.New("cloudflare: invalid record id")
	}
	return c.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zone)+"/dns_records/"+url.PathEscape(rec), nil, nil)
}
