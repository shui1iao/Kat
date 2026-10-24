package group

import (
	"net"

	"github.com/shui1iao/Kat/internal/outbound"
)

// serverRefused reports whether a member's dial error means that the member's
// proxy server refused the TCP connection itself: the local socket's connect
// (a *net.OpError with Op "dial", as returned by net.Dialer) failed with
// ECONNREFUSED. url-test re-tests at once on such an error (the "proxy server
// refused the connection" case of Surge's url-test re-test rules); every other
// failure keeps the urlTestFailCount-in-urlTestFailWindow rule.
//
// Deliberately conservative:
//   - direct members and nested groups never qualify: there the refusing
//     side may be the destination (or a group's direct member), not a proxy;
//   - a refusal reported by a proxy that was reached (SOCKS5 reply code,
//     AnyTLS "server refused stream", Trojan/SS closing after the first
//     write) is not a local socket error and does not qualify, even when its
//     text says "connection refused";
//   - in a chain only the local socket counts, i.e. the first hop's server
//     refusing; a refusal relayed by an earlier hop is a protocol reply and
//     does not qualify.
//
// The protocol packages return the under-dialer's error wrapped with %w and
// never build net.OpError or syscall errors for remote conditions; requiring
// Op "dial" also keeps an ECONNREFUSED wrapped without a local dial from
// matching.
func serverRefused(m outbound.Outbound, err error) bool {
	switch m.Type() {
	case "direct", TypeSelect, TypeURLTest, TypeFallback, TypeSmart:
		return false
	}
	return localDialRefused(err)
}

// localDialRefused walks err's wrap tree (including errors.Join) for a dial
// *net.OpError caused by a connection refusal.
func localDialRefused(err error) bool {
	if err == nil {
		return false
	}
	if op, ok := err.(*net.OpError); ok && op.Op == "dial" && isConnRefused(op.Err) {
		return true
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		return localDialRefused(u.Unwrap())
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if localDialRefused(e) {
				return true
			}
		}
	}
	return false
}
