package kernel

import (
	"github.com/shui1iao/Kat/internal/ss"
	"net"
)

// ssDownReadConn limits only SS2017 target reads into the existing relay
// buffer to one AEAD-2017 TCP record payload (ss.MaxChunk2017), so a 16384B
// relay buffer no longer yields a 16383B record plus a 1B tail record. The
// read view keeps the original backing; the pool still owns and returns its
// full allocation. Forward real target half-close; embedding net.Conn alone
// would hide it from closeWrite. All other methods pass through embedding.
type ssDownReadConn struct{ net.Conn }

func (c *ssDownReadConn) Read(p []byte) (int, error) {
	return c.Conn.Read(p[:min(len(p), ss.MaxChunk2017)])
}

func (c *ssDownReadConn) CloseWrite() error { return closeWrite(c.Conn) }

// ssDownTarget wraps the dialed target only for SS2017 (AEAD-2017) TCP relays.
// SS2022, every other protocol and all UDP paths keep the original target.
func ssDownTarget(in Inbound, out net.Conn) net.Conn {
	if in.ssRuntime != nil && !in.ssRuntime.v2022 {
		return &ssDownReadConn{out}
	}
	return out
}
