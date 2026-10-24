package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const version = "0.6.1"

func execute(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		fmt.Println("kat", version)
		return nil
	}
	if len(args) != 2 || (args[0] != "check" && args[0] != "run") {
		return fmt.Errorf("usage: kat {check|run} CONFIG.json | version")
	}
	c, e := kernel.Load(args[1])
	if e != nil {
		return fmt.Errorf("configuration_rejected")
	}
	if args[0] == "check" {
		fmt.Println("configuration valid")
		return nil
	}
	s, e := kernel.Start(c)
	if e != nil {
		return fmt.Errorf("startup_failed")
	}
	for _, a := range s.Addresses() {
		kernel.WriteDiagnosticLine(fmt.Sprintln("listening", a))
	}
	for _, b := range s.SSUDPReceiveBuffers() {
		kernel.WriteDiagnosticLine(fmt.Sprintf("ss2017 udp_rcvbuf %s default=%d actual=%d charged=%d\n", b.Address, b.Default, b.Actual, b.Charged))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	drain, cancel := context.WithTimeout(context.Background(), time.Duration(c.Limits.DrainTimeout))
	defer cancel()
	if e := s.Close(drain); e != nil {
		kernel.WriteDiagnosticLine("kat event=shutdown reason=drain_deadline\n")
	}
	kernel.WriteDiagnosticLine("kat event=stopped\n")
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
func main() {
	if e := execute(os.Args[1:]); e != nil {
		kernel.WriteDiagnosticLine("kat event=exit reason=" + e.Error() + "\n")
		os.Exit(1)
	}
}
