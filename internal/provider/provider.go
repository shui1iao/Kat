// Package provider parses subscription content ("proxy providers") into Kat
// outbound options. Supported inputs:
//
//   - Clash / mihomo YAML: the top-level "proxies" list (a whole mihomo
//     configuration works too; everything except "proxies" is ignored);
//   - URI lists: ss:// (SIP002, including the SIP022 plain "method:password"
//     userinfo, and the legacy whole-base64 form), trojan://, anytls://,
//     socks5:// (also socks:// and socks5h://), one per line, optionally
//     base64 encoded as a whole (standard or URL-safe, with or without
//     padding); blank lines and lines starting with # or // are ignored;
//   - sing-box JSON: the "outbounds" array (or a bare array of outbounds).
//
// Only node types Kat can dial are produced: shadowsocks (no SIP003 plugin),
// trojan and anytls over plain TLS/TCP, and SOCKS5 without TLS. Everything
// else is reported in Result.Skipped with the reason; credentials and raw
// lines are never part of a report.
//
// uTLS fingerprints (mihomo client-fingerprint, URI fp=, sing-box
// tls.utls.fingerprint) are retained in Node.ClientFingerprint and applied
// to cloned TLS options by OutboundOptions.
package provider

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/anytls"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
	"github.com/shui1iao/Kat/internal/outbound/ss"
	"github.com/shui1iao/Kat/internal/outbound/trojan"
)

// Limits.
const (
	MaxNodes    = 1024    // nodes kept per provider
	MaxSize     = 8 << 20 // subscription body
	MaxNameSize = 128     // bytes of a node name
)

// Formats.
const (
	FormatAuto    = "auto"
	FormatClash   = "clash"
	FormatURI     = "uri"
	FormatSingBox = "sing-box"
)

// Node is one usable node.
type Node struct {
	Options outbound.Options
	// ClientFingerprint is the uTLS fingerprint requested by the
	// subscription. OutboundOptions applies it without mutating the snapshot.
	ClientFingerprint string
	// Ignored lists subscription fields that were accepted but have no
	// effect in Kat (for example tfo, udp-over-tcp, idle-session tuning).
	Ignored []string
}

// OutboundOptions returns the runtime options without changing the provider
// snapshot. Browser fingerprints and certificate pins are separate settings.
func (n Node) OutboundOptions() outbound.Options {
	o := n.Options
	if n.ClientFingerprint != "" && (o.Type == "trojan" || o.Type == "anytls") {
		t := outbound.TLSOptions{}
		if o.TLS != nil {
			t = *o.TLS
		}
		t.Fingerprint = n.ClientFingerprint
		o.TLS = &t
	}
	return o
}

// Skipped is one entry that was not turned into a node.
type Skipped struct {
	Name   string // node name when known, else "#<entry number>"
	Type   string // declared type or URI scheme when known
	Reason string
}

// Result is the parsed content of one subscription.
type Result struct {
	Format  string // clash | uri | uri-base64 | sing-box
	Nodes   []Node
	Skipped []Skipped
	Renamed [][2]string // duplicate names: {original, new}
}

// ErrFormat: the content is not in any supported format (or has no entry).
var ErrFormat = errors.New("unrecognized subscription format")

// Parse parses b in the given format (empty = auto detection).
func Parse(b []byte, format string) (Result, error) {
	if len(b) > MaxSize {
		return Result{}, fmt.Errorf("subscription larger than %d bytes", MaxSize)
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	t := bytes.TrimSpace(b)
	var r Result
	var err error
	switch format {
	case FormatSingBox:
		r, err = parseSingBox(t)
	case FormatClash:
		r, err = parseClash(t)
	case FormatURI:
		r, err = parseURIBody(t)
	case "", FormatAuto:
		switch {
		case isClash(t):
			r, err = parseClash(t)
		case len(t) > 0 && (t[0] == '{' || t[0] == '['):
			r, err = parseSingBox(t)
		default:
			r, err = parseURIBody(t)
		}
	default:
		return Result{}, fmt.Errorf("unknown format %q", format)
	}
	if err != nil {
		return Result{}, err
	}
	r.dedupe()
	return r, nil
}

// add validates o and appends it as a node, or records why it was skipped.
func (r *Result) add(n Node, typ string) {
	name, ok := cleanName(n.Options.Name)
	if !ok {
		r.skip(n.Options.Name, typ, "missing or invalid node name")
		return
	}
	n.Options.Name = name
	if len(r.Nodes) >= MaxNodes {
		r.skip(name, typ, fmt.Sprintf("provider node limit (%d) reached", MaxNodes))
		return
	}
	if e := Validate(n.OutboundOptions()); e != nil {
		r.skip(name, typ, "invalid for Kat: "+e.Error())
		return
	}
	r.Nodes = append(r.Nodes, n)
}

func (r *Result) skip(name, typ, reason string) {
	if n, ok := cleanName(name); ok {
		name = n
	} else {
		name = fmt.Sprintf("#%d", len(r.Nodes)+len(r.Skipped)+1)
	}
	r.Skipped = append(r.Skipped, Skipped{Name: name, Type: typ, Reason: reason})
}

// dedupe renames later duplicates within one provider: "name#2", "name#3", ...
func (r *Result) dedupe() {
	seen := map[string]bool{}
	for i := range r.Nodes {
		seen[r.Nodes[i].Options.Name] = false
	}
	used := map[string]bool{}
	for i := range r.Nodes {
		n := r.Nodes[i].Options.Name
		if !used[n] {
			used[n] = true
			continue
		}
		for k := 2; ; k++ {
			c := SuffixedName(n, fmt.Sprintf("#%d", k))
			if _, taken := seen[c]; !taken && !used[c] {
				used[c] = true
				r.Renamed = append(r.Renamed, [2]string{n, c})
				r.Nodes[i].Options.Name = c
				break
			}
		}
	}
}

// Validate applies the owning protocol's strict validation.
func Validate(o outbound.Options) error {
	switch o.Type {
	case "shadowsocks":
		return ss.Validate(o)
	case "trojan":
		return trojan.Validate(o)
	case "anytls":
		return anytls.Validate(o)
	case "socks5":
		return socks5.Validate(o)
	}
	return errors.New("unsupported type")
}

// cleanName trims a node name and checks it: valid UTF-8, no control
// characters, 1..MaxNameSize bytes.
func cleanName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxNameSize || !utf8.ValidString(s) {
		return "", false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return "", false
		}
	}
	return s, true
}

// decodeBase64 accepts standard and URL-safe alphabets, with or without
// padding, ignoring whitespace.
func decodeBase64(s string) ([]byte, bool) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(s); e == nil {
			return b, true
		}
	}
	return nil, false
}

// SuffixedName appends a collision suffix, truncating only the original name
// at a UTF-8 boundary so the final provider name stays within MaxNameSize.
func SuffixedName(name, suffix string) string {
	limit := MaxNameSize - len(suffix)
	if len(name) > limit {
		name = name[:limit]
		for !utf8.ValidString(name) {
			name = name[:len(name)-1]
		}
	}
	return name + suffix
}

func boolPtr(v bool) *bool { return &v }
