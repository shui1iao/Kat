package route

import (
	"context"
	"errors"
	"net"
	"strings"
)

// CheckFiles loads the local rule set, GeoIP, geosite and ASN files the way
// the engine does (no download) and returns an error describing every file
// whose content is rejected: unsupported rule types or options, invalid
// content or exceeded limits. A missing file is not an error here (it may be
// downloaded, and the server reports it when it starts).
func CheckFiles(o Options) error {
	var problems []string
	sink := func(event string, kv ...string) {
		if !strings.HasSuffix(event, "_update_failed") {
			return
		}
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		if m["class"] == classMissing {
			return
		}
		p := strings.TrimSuffix(event, "_update_failed")
		if m["name"] != "" {
			p += " " + m["name"]
		}
		p += ": " + m["class"]
		if m["detail"] != "" {
			p += " (" + m["detail"] + ")"
		}
		problems = append(problems, p)
	}
	noDial := func(string) (func(context.Context, string, string) (net.Conn, error), error) {
		return nil, errors.New("no download in check")
	}
	e, err := NewEngine(o, noDial, sink)
	if err != nil {
		return err
	}
	e.Close()
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}
