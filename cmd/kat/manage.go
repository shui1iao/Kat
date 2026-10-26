package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/stats"
)

// instancePaths are the per-configuration default locations.
type instancePaths struct{ socket, stats string }

// instanceName derives the instance name from the configuration file name:
// "/etc/kat/ss.json" -> "ss". Characters outside [A-Za-z0-9._-] become "_".
func instanceName(config string) string {
	base := filepath.Base(config)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	b := []byte(base)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			b[i] = '_'
		}
	}
	name := strings.Trim(string(b), ".")
	if name == "" {
		name = "kat"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func defaultPaths(config string) instancePaths {
	name := instanceName(config)
	run, state := defaultDirs()
	return instancePaths{socket: filepath.Join(run, name+".sock"), stats: filepath.Join(state, name+".stats.json")}
}

type cli struct {
	config, socket string
	json, all      bool
	rest           []string
}

func parseCLI(args []string) (cli, error) {
	var c cli
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" || a == "--config" || a == "--socket":
			if i+1 >= len(args) {
				return c, cliError{a + " requires a value"}
			}
			i++
			if a == "--socket" {
				c.socket = args[i]
			} else {
				c.config = args[i]
			}
		case strings.HasPrefix(a, "--config="):
			c.config = strings.TrimPrefix(a, "--config=")
		case strings.HasPrefix(a, "--socket="):
			c.socket = strings.TrimPrefix(a, "--socket=")
		case a == "--json":
			c.json = true
		case a == "--all":
			c.all = true
		case strings.HasPrefix(a, "-") && a != "-":
			return c, cliError{"unknown option " + a + "\n" + usage}
		default:
			c.rest = append(c.rest, a)
		}
	}
	if c.config != "" && c.socket != "" {
		return c, cliError{"use either -c CONFIG or --socket PATH"}
	}
	return c, nil
}

// resolveSocket finds the management socket: --socket, the "api.socket" of
// the configuration given with -c, its default path, or the only socket in
// the default directory.
func resolveSocket(c cli) (string, error) {
	if c.socket != "" {
		return c.socket, nil
	}
	if c.config != "" {
		if b, e := os.ReadFile(c.config); e == nil {
			var partial struct {
				API *struct {
					Enabled *bool  `json:"enabled"`
					Socket  string `json:"socket"`
				} `json:"api"`
			}
			if json.Unmarshal(b, &partial) == nil && partial.API != nil {
				if partial.API.Enabled != nil && !*partial.API.Enabled {
					return "", cliError{"the management API is disabled in " + c.config}
				}
				if partial.API.Socket != "" {
					return partial.API.Socket, nil
				}
			}
		}
		name := instanceName(c.config)
		cands := socketCandidates(name)
		for _, p := range cands {
			if _, e := os.Stat(p); e == nil {
				return p, nil
			}
		}
		return cands[0], nil
	}
	run, _ := defaultDirs()
	found, _ := filepath.Glob(filepath.Join(run, "*.sock"))
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", cliError{"no Kat management socket found in " + run + "; use -c CONFIG.json or --socket PATH"}
	}
	return "", cliError{"several Kat instances are running (" + strings.Join(found, ", ") + "); use -c CONFIG.json or --socket PATH"}
}

type apiClient struct {
	socket string
	hc     *http.Client
}

func newClient(socket string) *apiClient {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	return &apiClient{socket, &http.Client{Transport: tr, Timeout: 15 * time.Second}}
}

type apiError struct {
	status int
	code   string
	stage  string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func (c *apiClient) do(method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://kat"+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := c.hc.Do(req)
	if e != nil {
		if errors.Is(e, os.ErrPermission) || strings.Contains(e.Error(), "permission denied") {
			return cliError{"permission denied for " + c.socket + " (the socket is private to the user running Kat)"}
		}
		return cliError{"cannot reach the Kat management socket " + c.socket + ": " + rootCause(e)}
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if e != nil {
		return cliError{"incomplete response from " + c.socket}
	}
	if resp.StatusCode != http.StatusOK {
		var ae struct{ Error, Stage, Message string }
		_ = json.Unmarshal(b, &ae)
		return &apiError{resp.StatusCode, ae.Error, ae.Stage, ae.Message}
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], b...)
		return nil
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func rootCause(e error) string {
	for {
		u := errors.Unwrap(e)
		if u == nil {
			return e.Error()
		}
		e = u
	}
}

func manage(args []string, w io.Writer) error {
	c, e := parseCLI(args[1:])
	if e != nil {
		return e
	}
	cmd := args[0]
	sub := ""
	if len(c.rest) > 0 {
		sub = c.rest[0]
	}
	socket, e := resolveSocket(c)
	if e != nil {
		return e
	}
	cl := newClient(socket)
	switch {
	case cmd == "stats" && sub == "":
		var raw json.RawMessage
		if e := cl.do("GET", "/v1/stats", nil, &raw); e != nil {
			return apiFail(e)
		}
		if c.json {
			_, e := w.Write(raw)
			return e
		}
		var v kernel.StatsView
		if e := json.Unmarshal(raw, &v); e != nil {
			return cliError{"unexpected stats response"}
		}
		printStats(w, v)
		return nil
	case cmd == "stats" && sub == "reset" && len(c.rest) == 1:
		var r struct{ Saved bool }
		if e := cl.do("POST", "/v1/stats/reset", nil, &r); e != nil {
			return apiFail(e)
		}
		if r.Saved {
			fmt.Fprintln(w, "statistics reset")
		} else {
			fmt.Fprintln(w, "statistics reset (not persisted: saving failed or persistence is off)")
		}
		return nil
	case cmd == "conns" && sub == "":
		var raw json.RawMessage
		if e := cl.do("GET", "/v1/connections", nil, &raw); e != nil {
			return apiFail(e)
		}
		if c.json {
			_, e := w.Write(raw)
			return e
		}
		var list []kernel.ConnInfo
		if e := json.Unmarshal(raw, &list); e != nil {
			return cliError{"unexpected connections response"}
		}
		printConns(w, list)
		return nil
	case cmd == "conns" && sub == "close":
		if c.all && len(c.rest) == 1 {
			var r struct{ Closed int }
			if e := cl.do("DELETE", "/v1/connections", nil, &r); e != nil {
				return apiFail(e)
			}
			fmt.Fprintf(w, "closed %d connection(s)\n", r.Closed)
			return nil
		}
		if c.all || len(c.rest) != 2 {
			return cliError{"usage: kat conns close ID|--all"}
		}
		id, e := strconv.ParseUint(c.rest[1], 10, 64)
		if e != nil || id == 0 {
			return cliError{"connection ID must be a positive integer"}
		}
		if e := cl.do("DELETE", "/v1/connections/"+strconv.FormatUint(id, 10), nil, nil); e != nil {
			return apiFail(e)
		}
		fmt.Fprintf(w, "closed connection %d\n", id)
		return nil
	case cmd == "log" && sub == "level" && len(c.rest) <= 2:
		var r struct{ Level string }
		if len(c.rest) == 2 {
			if e := cl.do("PUT", "/v1/log/level", map[string]string{"level": c.rest[1]}, &r); e != nil {
				return apiFail(e)
			}
			fmt.Fprintf(w, "log level set to %s\n", r.Level)
			return nil
		}
		if e := cl.do("GET", "/v1/log/level", nil, &r); e != nil {
			return apiFail(e)
		}
		fmt.Fprintln(w, r.Level)
		return nil
	case cmd == "reload" && len(c.rest) == 0:
		var r kernel.ReloadResult
		if e := cl.do("POST", "/v1/reload", nil, &r); e != nil {
			var ae *apiError
			if errors.As(e, &ae) && ae.code == "reload_failed" {
				stage := ae.stage
				if stage == "" {
					stage = "unknown"
				}
				return cliError{"reload failed (" + stage + "): " + ae.msg + "; the running configuration is unchanged"}
			}
			return apiFail(e)
		}
		fmt.Fprintf(w, "configuration reloaded (generation %d, %d ms)\n", r.Generation, r.DurationMS)
		return nil
	case cmd == "select" && len(c.rest) == 0:
		var raw json.RawMessage
		if e := cl.do("GET", "/v1/select", nil, &raw); e != nil {
			return apiFail(e)
		}
		if c.json {
			_, e := w.Write(raw)
			return e
		}
		var list []kernel.SelectGroup
		if e := json.Unmarshal(raw, &list); e != nil {
			return cliError{"unexpected select response"}
		}
		if len(list) == 0 {
			fmt.Fprintln(w, "no select groups")
			return nil
		}
		for _, g := range list {
			src := "configuration"
			if g.Source == "runtime" {
				src = "runtime choice"
			}
			fmt.Fprintf(w, "%s: %s (%s; configured %s)\n  members: %s\n", g.Name, g.Current, src, g.Default, strings.Join(g.Members, ", "))
		}
		return nil
	case cmd == "bans" && len(c.rest) == 0:
		var raw json.RawMessage
		if e := cl.do("GET", "/v1/bans", nil, &raw); e != nil {
			return apiFail(e)
		}
		if c.json {
			_, e := w.Write(raw)
			return e
		}
		var list []kernel.BanInfo
		if e := json.Unmarshal(raw, &list); e != nil {
			return cliError{"unexpected bans response"}
		}
		if len(list) == 0 {
			fmt.Fprintln(w, "no banned sources")
			return nil
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SOURCE\tPROTOCOL\tFAILURES\tSINCE\tREMAINING")
		now := time.Now()
		for _, b := range list {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", b.Source, b.Protocol, b.Failures, b.Since.Local().Format("15:04:05"), b.Until.Sub(now).Round(time.Second))
		}
		return tw.Flush()
	case cmd == "bans" && len(c.rest) == 2 && c.rest[0] == "remove":
		var r map[string]any
		if e := cl.do("DELETE", "/v1/bans/"+url.PathEscape(c.rest[1]), nil, &r); e != nil {
			var ae *apiError
			if errors.As(e, &ae) && (ae.code == "not_found" || ae.code == "bad_source") {
				return cliError{c.rest[1] + ": " + ae.msg}
			}
			return apiFail(e)
		}
		fmt.Fprintf(w, "%s: ban removed\n", c.rest[1])
		return nil
	case cmd == "select" && len(c.rest) == 2:
		if e := cl.do("PUT", "/v1/select/"+url.PathEscape(c.rest[0]), map[string]string{"member": c.rest[1]}, nil); e != nil {
			return apiFail(e)
		}
		fmt.Fprintf(w, "%s: selected %s (new connections only)\n", c.rest[0], c.rest[1])
		return nil
	}
	return cliError{usage}
}

func apiFail(e error) error {
	var ae *apiError
	if errors.As(e, &ae) {
		switch ae.code {
		case "details_disabled":
			return cliError{"connection details are disabled; set \"stats\": {\"connections\": true} in the configuration to list or close connections"}
		case "not_found":
			if ae.msg != "" && ae.msg != "no active connection with this id" {
				return cliError{ae.msg}
			}
			return cliError{"no active connection with this ID"}
		}
		if ae.msg != "" {
			return cliError{ae.msg}
		}
		return cliError{fmt.Sprintf("management API returned HTTP %d", ae.status)}
	}
	return e
}

func human(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n), -1
	for v >= unit && i < 4 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.2f %ciB", v, "KMGTP"[i])
}

func rate(v float64) string { return human(uint64(v)) + "/s" }

func printStats(w io.Writer, v kernel.StatsView) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	c := v.Cumulative
	fmt.Fprintf(tw, "kat %s\tuptime %s\tcounting since %s\n", v.Version, (time.Duration(v.UptimeMS) * time.Millisecond).Round(time.Second), c.Since.Local().Format(time.RFC3339))
	fmt.Fprintf(tw, "total\tup %s (%d)\tdown %s (%d)\n", human(c.Total.Up), c.Total.Up, human(c.Total.Down), c.Total.Down)
	fmt.Fprintf(tw, "rate (%.0fs)\tup %s\tdown %s\n", float64(v.Rate.WindowMS)/1000, rate(v.Rate.Up), rate(v.Rate.Down))
	fmt.Fprintf(tw, "connections\ttcp %d\tudp %d\taccepted %d\trejected since start %d\n", v.Connections.TCP, v.Connections.UDP, v.Connections.Accepted, v.Connections.Rejected)
	if v.Persist.Enabled {
		last := "never"
		if !v.Persist.LastSave.IsZero() {
			last = v.Persist.LastSave.Local().Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "persist\t%s\tlast save %s\tsave errors %d\n", v.Persist.File, last, v.Persist.SaveErrors)
	} else {
		fmt.Fprintf(tw, "persist\toff\t\t\n")
	}
	section := func(title string, list []stats.Named) {
		fmt.Fprintf(tw, "%s:\t\t\n", title)
		for _, n := range list {
			fmt.Fprintf(tw, "  %s\tup %s (%d)\tdown %s (%d)\n", n.Name, human(n.Up), n.Up, human(n.Down), n.Down)
		}
	}
	section("inbounds", c.Inbounds)
	section("outbounds", c.Outbounds)
	if len(c.Groups) > 0 {
		section("groups", c.Groups)
	}
	fmt.Fprintf(tw, "rules:\t\t\n")
	for _, r := range c.Rules {
		fmt.Fprintf(tw, "  %s\thits %d\tup %s (%d)\tdown %s (%d)\n", r.Name, r.Hits, human(r.Up), r.Up, human(r.Down), r.Down)
	}
	tw.Flush()
}

func printConns(w io.Writer, list []kernel.ConnInfo) {
	if len(list) == 0 {
		fmt.Fprintln(w, "no active connections")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNET\tINBOUND\tSOURCE\tTARGET\tRULE\tCHAIN\tSTART\tDURATION\tUP\tDOWN")
	for _, c := range list {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.Network, c.Inbound, c.Source, dashed(c.Target), dashed(c.Rule), dashed(strings.Join(c.Chain, ">")),
			c.Start.Local().Format("15:04:05"), (time.Duration(c.DurationMS) * time.Millisecond).Round(time.Second), human(c.Up), human(c.Down))
	}
	tw.Flush()
}

func dashed(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
