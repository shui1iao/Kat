package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const version = "0.7.1"

const usage = `usage:
  kat check CONFIG.json
  kat run CONFIG.json
  kat version
  kat stats [--json] [-c CONFIG.json | --socket PATH]
  kat stats reset [-c CONFIG.json | --socket PATH]
  kat conns [--json] [-c CONFIG.json | --socket PATH]
  kat conns close ID|--all [-c CONFIG.json | --socket PATH]
  kat log level [debug|info|warn|error] [-c CONFIG.json | --socket PATH]
  kat reload [-c CONFIG.json | --socket PATH]
  kat select [--json] [-c CONFIG.json | --socket PATH]
  kat select GROUP MEMBER [-c CONFIG.json | --socket PATH]
  kat bans [--json] [-c CONFIG.json | --socket PATH]
  kat bans remove SOURCE [-c CONFIG.json | --socket PATH]`

// cliError is a management command failure printed as "kat: MESSAGE".
type cliError struct{ msg string }

func (e cliError) Error() string { return e.msg }

func execute(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		fmt.Println("kat", version)
		return nil
	}
	if len(args) >= 1 {
		switch args[0] {
		case "stats", "conns", "log", "reload", "select", "bans":
			return manage(args, os.Stdout)
		}
	}
	if len(args) != 2 || (args[0] != "check" && args[0] != "run") {
		return fmt.Errorf("usage: kat {check|run} CONFIG.json | version | stats | conns | log level | reload | select | bans")
	}
	c, e := kernel.Load(args[1])
	if e != nil {
		return fmt.Errorf("configuration_rejected")
	}
	if args[0] == "check" {
		paths := defaultPaths(args[1])
		c.ApplyDefaultPaths(paths.socket, paths.stats)
		c.ApplyDefaultStateDir(filepath.Dir(paths.stats))
		if e := c.CheckRouteFiles(); e != nil {
			return cliError{"rule data rejected: " + e.Error()}
		}
		reps, groups, err := kernel.CheckProviders(c)
		if err != nil {
			return fmt.Errorf("configuration_rejected: %v", err)
		}
		fmt.Println("configuration valid")
		for _, p := range reps {
			fmt.Printf("provider %q type=%s source=%s format=%s nodes=%d skipped=%d\n", p.Name, p.Type, p.Source, p.Format, len(p.Nodes), len(p.Skipped))
			if p.Error != "" {
				fmt.Printf("  unavailable: %s\n", p.Error)
			}
			for _, v := range p.Skipped {
				fmt.Printf("  skipped name=%q type=%q reason=%q\n", v.Name, v.Type, v.Reason)
			}
			for _, v := range p.Renamed {
				fmt.Printf("  renamed %q -> %q\n", v[0], v[1])
			}
			for _, v := range p.Ignored {
				fmt.Printf("  ignored %q\n", v)
			}
			for _, v := range p.Fingerprints {
				fmt.Printf("  TLS fingerprint %q\n", v)
			}
		}
		for _, g := range groups {
			fmt.Printf("group %q type=%s members=%d\n", g.Name, g.Type, g.Members)
		}
		return nil
	}
	kernel.Version = version
	paths := defaultPaths(args[1])
	c.ApplyDefaultPaths(paths.socket, paths.stats)
	c.ApplyDefaultStateDir(filepath.Dir(paths.stats))
	s, e := kernel.Start(c)
	if e != nil {
		return fmt.Errorf("startup_failed")
	}
	// kat reload and SIGHUP read the same file again, with the same defaults.
	path := args[1]
	s.SetConfigLoader(func() (kernel.Config, error) {
		c, e := kernel.Load(path)
		if e != nil {
			return c, explainLoad(path, e)
		}
		c.ApplyDefaultPaths(paths.socket, paths.stats)
		c.ApplyDefaultStateDir(filepath.Dir(paths.stats))
		return c, nil
	})
	for _, a := range s.Addresses() {
		s.Info(fmt.Sprintln("listening", a))
	}
	for _, b := range s.SSUDPReceiveBuffers() {
		s.Info(fmt.Sprintf("ss2017 udp_rcvbuf %s default=%d actual=%d charged=%d\n", b.Address, b.Default, b.Actual, b.Charged))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// SIGHUP reloads the configuration (0.6.x exited on SIGHUP).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
wait:
	for {
		select {
		case <-ctx.Done():
			break wait
		case <-hup:
			_, _ = s.Reload("sighup") // the result is logged by the server
		}
	}
	c = s.CurrentConfig()
	drain, cancel := context.WithTimeout(context.Background(), time.Duration(c.Limits.DrainTimeout))
	defer cancel()
	if e := s.Close(drain); e != nil {
		kernel.FinalLine(&c, "warn", "kat event=shutdown reason=drain_deadline\n")
	}
	kernel.FinalLine(&c, "info", "kat event=stopped\n")
	if os.Getenv("KAT_TEST_DIAGNOSTICS") == "1" {
		local := true
		for _, in := range c.Inbounds {
			h, _, _ := net.SplitHostPort(in.Listen)
			if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
				local = false
			}
		}
		if local {
			b, _ := json.Marshal(s.Diagnostics())
			kernel.WriteDiagnosticLine(string(b) + "\n")
		}
	}
	return nil
}

// explainLoad adds the line of a JSON syntax error to a reload failure.
func explainLoad(path string, e error) error {
	b, re := os.ReadFile(path)
	if re != nil {
		return e
	}
	var v any
	var se *json.SyntaxError
	if je := json.Unmarshal(b, &v); errors.As(je, &se) {
		line := 1 + bytes.Count(b[:min(int(se.Offset), len(b))], []byte("\n"))
		return fmt.Errorf("%v (line %d: %s)", e, line, se.Error())
	}
	return e
}

func main() {
	if e := execute(os.Args[1:]); e != nil {
		var ce cliError
		if errors.As(e, &ce) {
			fmt.Fprintln(os.Stderr, "kat:", ce.msg)
			os.Exit(1)
		}
		kernel.WriteDiagnosticLine("kat event=exit reason=" + e.Error() + "\n")
		os.Exit(1)
	}
}
