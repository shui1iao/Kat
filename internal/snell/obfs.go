package snell

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

type httpTransport struct {
	io.ReadWriteCloser
	r        *bufio.Reader
	readHead bool
	sent     bool
}

func (h *httpTransport) Read(p []byte) (int, error) {
	if !h.readHead {
		match := 0
		term := "\r\n\r\n"
		for count := 0; match < 4; count++ {
			if count >= 8192 {
				return 0, ErrLimit
			}
			b, e := h.r.ReadByte()
			if e != nil {
				return 0, e
			}
			if b == term[match] {
				match++
			} else if b == term[0] {
				match = 1
			} else {
				match = 0
			}
		}
		h.readHead = true
	}
	return h.r.Read(p)
}
func (h *httpTransport) Write(p []byte) (int, error) {
	if !h.sent {
		var token [16]byte
		if _, e := rand.Read(token[:]); e != nil {
			return 0, e
		}
		head := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nDate: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", time.Now().UTC().Format(time.RFC1123), base64.StdEncoding.EncodeToString(token[:]))
		if e := writeAll(h.ReadWriteCloser, []byte(head)); e != nil {
			return 0, e
		}
		h.sent = true
	}
	return h.ReadWriteCloser.Write(p)
}
