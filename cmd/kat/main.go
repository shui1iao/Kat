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

const version = "0.5.20"

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
		return e
	}
	if args[0] == "check" {
		fmt.Println("configuration valid")
		return nil
	}
	s, e := kernel.Start(c)
	if e != nil {
		return e
	}
	for _, a := range s.Addresses() {
		fmt.Fprintln(os.Stderr, "listening", a)
	}
	for _, b := range s.SSUDPReceiveBuffers() {
		fmt.Fprintf(os.Stderr, "ss2017 udp_rcvbuf %s default=%d actual=%d charged=%d\n", b.Address, b.Default, b.Actual, b.Charged)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	drain, cancel := context.WithTimeout(context.Background(), time.Duration(c.Limits.DrainTimeout))
	defer cancel()
	_ = s.Close(drain)
	if os.Getenv("KAT_TEST_DIAGNOSTICS") == "1" {
		local := true
		for _, in := range c.Inbounds {
			h, _, _ := net.SplitHostPort(in.Listen)
			if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
				local = false
			}
		}
		if local {
			_ = json.NewEncoder(os.Stderr).Encode(s.Diagnostics())
		}
	}
	return nil
}
func main() {
	if e := execute(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "error:", e)
		os.Exit(1)
	}
}
