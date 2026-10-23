// Copyright (c) 2023 RPRX. Original detection API retained.
// Stage changes (2026-10-18) are governed by MPL-2.0; see LICENSE.
// Bounded public-API preflight replaces unbounded asynchronous detection.
package reality

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

var GlobalPostHandshakeRecordsLens sync.Map
var GlobalMaxCSSMsgCount sync.Map

// DetectPostHandshakeRecordsLens is the bounded compatibility entry point.
// New integrations should use the error-returning Context variant before Serve.
func DetectPostHandshakeRecordsLens(config *Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = DetectPostHandshakeRecordsLensContext(ctx, config)
}

// DetectPostHandshakeRecordsLensContext synchronously authenticates the decoy
// certificate, samples actual post-handshake record lengths, and returns only
// after all sockets close. No fake empty profile is installed on failure.
// Config.RootCAs must trust a local/private decoy; nil uses the system roots.
func DetectPostHandshakeRecordsLensContext(ctx context.Context, c *Config) error {
	if c == nil || c.DialContext == nil || len(c.ServerNames) == 0 || len(c.ServerNames) > 8 || c.Xver != 0 {
		return errors.New("REALITY: invalid bounded preflight config")
	}
	profiles := make(map[string][]int)
	for sni := range c.ServerNames {
		for alpn := 0; alpn < 3; alpn++ {
			p, e := detectOne(ctx, c, sni, alpn)
			if e != nil {
				return fmt.Errorf("REALITY preflight %s/%d: %w", sni, alpn, e)
			}
			key := c.Dest + " " + sni + " " + strconv.Itoa(alpn)
			profiles[key] = p
		}
	}
	c.PostHandshakeProfiles = profiles
	return nil
}
func detectOne(parent context.Context, c *Config, sni string, alpn int) ([]int, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	conn, e := c.DialContext(ctx, c.Type, c.Dest)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, e
	}
	meter := &probeRecordConn{Conn: conn}
	protos := []string(nil)
	finger := utls.HelloGolang
	if alpn == 1 {
		protos = []string{"http/1.1"}
	}
	if alpn == 2 {
		protos = []string{"h2", "http/1.1"}
		finger = utls.HelloChrome_Auto
	}
	client := utls.UClient(meter, &utls.Config{ServerName: sni, RootCAs: c.RootCAs, NextProtos: protos, MinVersion: utls.VersionTLS13}, finger)
	if e = client.HandshakeContext(ctx); e != nil {
		return nil, e
	}
	if !client.ConnectionState().HandshakeComplete {
		return nil, errors.New("incomplete handshake")
	}
	meter.capture = true
	if e = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); e != nil {
		return nil, e
	}
	var b [16384]byte
	for {
		n, err := client.Read(b[:])
		if n > 0 {
			return nil, errors.New("decoy sent unsolicited application data")
		}
		if err != nil {
			if parent.Err() != nil {
				return nil, parent.Err()
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	if meter.remaining != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return append([]int{}, meter.lengths...), nil
}

// Restrict reads to a single TLS record, preventing TLS-internal prefetch from
// hiding a post-handshake record. Ciphertext storage is bounded to the header.
type probeRecordConn struct {
	net.Conn
	header          [5]byte
	have, remaining int
	capture         bool
	lengths         []int
}

func (c *probeRecordConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.remaining == 0 {
		if c.have == 0 {
			if n, e := io.ReadFull(c.Conn, c.header[:]); e != nil {
				if n > 0 {
					return 0, io.ErrUnexpectedEOF
				}
				return 0, e
			}
			n := int(binary.BigEndian.Uint16(c.header[3:]))
			if n < 1 || n > 18432 {
				return 0, errors.New("invalid record size")
			}
			c.remaining = n
			c.have = 5
			if c.capture {
				if c.header[0] != 23 || len(c.lengths) >= 32 {
					return 0, errors.New("invalid post handshake record")
				}
				c.lengths = append(c.lengths, n+5)
			}
		}
	}
	if c.have > 0 {
		off := 5 - c.have
		n := copy(p, c.header[off:])
		c.have -= n
		return n, nil
	}
	n, e := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	return n, e
}
