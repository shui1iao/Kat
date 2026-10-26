package kernel

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// ---- 0.7.0 TCP Fast Open ----
//
// "tcp_fast_open" on an inbound sets TCP_FASTOPEN on its listening socket
// (also on a socket kept by a reload; turning it off sets the queue to 0).
// The root "direct": {"tcp_fast_open": true} sets TCP_FASTOPEN_CONNECT on
// every direct TCP dial (client destinations and first hops to proxy
// servers): data of the first write then rides in the SYN once the kernel
// holds a cookie for the destination. Both are off by default. Kat never
// changes net.ipv4.tcp_fastopen; it warns when the value does not enable the
// configured side (bit 1 = client, bit 2 = server).

// tfoSysctlPath is read by checkTFO (tests point it to a fixture).
var tfoSysctlPath = "/proc/sys/net/ipv4/tcp_fastopen"

const (
	tfoClientBit = 0x1
	tfoServerBit = 0x2
)

// tfoWarnings returns the warning lines for configuration c given the sysctl
// reader (nil error and value) — separated from checkTFO for tests.
func tfoWarnings(c *Config, read func() (int, error)) []string {
	inbound := false
	for _, in := range c.Inbounds {
		if in.TCPFastOpen {
			inbound = true
		}
	}
	direct := c.Direct != nil && c.Direct.TCPFastOpen
	if !inbound && !direct {
		return nil
	}
	if !tfoSupported {
		return []string{"kat event=tfo_unsupported reason=platform action=ignored"}
	}
	v, e := read()
	if e != nil {
		return []string{"kat event=tfo_sysctl_unreadable sysctl=net.ipv4.tcp_fastopen action=continue"}
	}
	var out []string
	if inbound && v&tfoServerBit == 0 {
		out = append(out, "kat event=tfo_sysctl_insufficient side=server sysctl=net.ipv4.tcp_fastopen value="+strconv.Itoa(v)+" required_bit=0x2 effect=inbound_tfo_inactive hint=set_net.ipv4.tcp_fastopen_to_3")
	}
	if direct && v&tfoClientBit == 0 {
		out = append(out, "kat event=tfo_sysctl_insufficient side=client sysctl=net.ipv4.tcp_fastopen value="+strconv.Itoa(v)+" required_bit=0x1 effect=direct_tfo_inactive hint=set_net.ipv4.tcp_fastopen_to_3")
	}
	return out
}

func readTFOSysctl() (int, error) {
	b, e := os.ReadFile(tfoSysctlPath)
	if e != nil {
		return 0, e
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// checkTFO warns about a sysctl that does not enable configured TFO.
func (k *core) checkTFO(c *Config) {
	for _, line := range tfoWarnings(c, readTFOSysctl) {
		k.notice(levelWarn, line)
	}
}

// applyTFO sets the TFO state of the listening sockets of generation g.
// The caller holds reloadMu.
func (k *core) applyTFO(g *Server, p *plan) {
	for i := range g.cfg.Inbounds {
		in := &g.cfg.Inbounds[i]
		e := k.tcpEntries[p.keys[i]]
		if e == nil || e.tfo == in.TCPFastOpen {
			continue
		}
		if err := setListenerTFO(e.ln, in.TCPFastOpen); err != nil {
			k.notice(levelWarn, "kat event=tfo_setsockopt_failed inbound="+strconv.Itoa(i)+" reason="+eventToken(err.Error(), 120))
			continue
		}
		e.tfo = in.TCPFastOpen
	}
}

// plainDialer is the net.Dialer of direct TCP dials.
func (s *Server) plainDialer() *net.Dialer {
	if s.directTFO() {
		return &net.Dialer{ControlContext: tfoDialControl}
	}
	return &net.Dialer{}
}

func (s *Server) directTFO() bool {
	return tfoSupported && s.cfg.Direct != nil && s.cfg.Direct.TCPFastOpen
}
