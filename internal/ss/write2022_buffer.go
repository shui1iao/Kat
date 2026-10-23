package ss

import (
	"encoding/binary"
	"io"
	"net"
)

// Write2022Buffers is used only by the SS2022 TCP down relay. Each wire has
// 18 bytes of headroom and16 bytes of tag room around its plaintext; the caller
// owns and MUST fully clear every lease after return. It seals only ALREADY-read
// records and issues one TCP writev. The lazy first response uses ordinary Write.
// No new batch is awaited, and all input leases remain owned/charged by the
// synchronous caller until return. The maximum eight records fit within the
// pre-existing process lease budget. Non-TCP test transports use writeAll.
func (c *TCPConn) Write2022Buffers(wires [][]byte) (int, error) {
	if c.reader.max != MaxChunk2022 || len(wires) > 8 {
		return 0, ErrFormat
	}
	if len(wires) == 0 {
		return 0, nil
	}
	for _, wire := range wires {
		if len(wire) <= 34 || len(wire)-34 > MaxChunk2022 {
			return 0, ErrFormat
		}
	}
	c.wMu.Lock()
	if c.werr != nil {
		err := c.werr
		c.wMu.Unlock()
		return 0, err
	}
	if c.writerAEAD == nil {
		c.wMu.Unlock()
		n, err := c.Write(wires[0][18 : len(wires[0])-16])
		if err != nil {
			return n, err
		}
		m, err := c.Write2022Buffers(wires[1:])
		return n + m, err
	}
	defer c.wMu.Unlock()
	prepared := 0
	var encodeErr error
	for _, wire := range wires {
		data := wire[18 : len(wire)-16]
		binary.BigEndian.PutUint16(wire[:2], uint16(len(data)))
		var header []byte
		header, encodeErr = sealAppend(c.writerAEAD, &c.writeNonce, wire[:0], wire[:2])
		if encodeErr == nil {
			_, encodeErr = sealAppend(c.writerAEAD, &c.writeNonce, header, data)
		}
		if encodeErr != nil {
			break
		}
		prepared++
	}
	total := 0
	var writeErr error
	if tcp, ok := c.transport.(*net.TCPConn); ok && prepared > 0 {
		// WriteTo consumes its slice headers, never the owned source list.
		var list [8][]byte
		copy(list[:], wires[:prepared])
		buffers := net.Buffers(list[:prepared])
		n, err := buffers.WriteTo(tcp)
		writeErr = err
		for _, wire := range wires[:prepared] {
			if n < int64(len(wire)) {
				if writeErr == nil {
					writeErr = io.ErrShortWrite
				}
				break
			}
			n -= int64(len(wire))
			total += len(wire) - 34
		}
	} else {
		for _, wire := range wires[:prepared] {
			if writeErr = writeAll(c.transport, wire); writeErr != nil {
				break
			}
			total += len(wire) - 34
		}
	}
	// Flush any complete prefix before surfacing a later nonce exhaustion, just
	// as sequential Write would. A transport failure takes precedence and poisons
	// the writer; no pre-encrypted nonce is ever reused after either failure.
	if writeErr != nil {
		c.werr = writeErr
		return total, writeErr
	}
	if encodeErr != nil {
		c.werr = encodeErr
		return total, encodeErr
	}
	return total, nil
}
