//go:build linux

package kernel

import (
	SS "github.com/shui1iao/Kat/internal/ss"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ss2022BatchPayload = ss2022DownBytes
const ss2022BatchRecords = 8

// Uses only the repartitioned <=16*65535-byte lease pool. Each buffer reserves the
// 18-byte encrypted length and 16-byte payload tag; no cipher workspace or
// connection-resident buffer is added. Unknown wrappers/platforms fall back.
func trySS2022DownBatch(dst, src net.Conn, target *ss2022DownConn, small int) (bool, error) {
	return trySS2022DownBatchM(dst, src, target, small, meter{})
}

func trySS2022DownBatchM(dst, src net.Conn, target *ss2022DownConn, small int, m meter) (bool, error) {
	tcp, ok := target.Conn.(*net.TCPConn)
	if !ok {
		return false, nil
	}
	writer := dst
	var last *activityStream
	if a, ok := dst.(*activityStream); ok {
		writer = a.Conn
		last = a
	}
	encrypted, ok := writer.(*encryptedStream)
	if !ok {
		return false, nil
	}
	codec, ok := encrypted.codec.(*SS.TCPConn)
	if !ok {
		return false, nil
	}
	ready := ss2022Ready(tcp)
	if ready <= small {
		return false, nil
	}
	count := min(ss2022BatchRecords, (ready+ss2022BatchPayload-1)/ss2022BatchPayload)
	var buffers [ss2022BatchRecords][]byte
	var vectors [ss2022BatchRecords]unix.Iovec
	got := 0
	for got < count {
		b := leaseSS2022Down()
		if b == nil {
			break
		}
		buffers[got] = b
		n := min(ss2022BatchPayload, ready-got*ss2022BatchPayload)
		vectors[got].Base = &b[18]
		vectors[got].SetLen(n)
		got++
	}
	if got == 0 {
		return false, nil
	}
	defer func() {
		for _, b := range buffers[:got] {
			releaseSS2022Down(b)
		}
	}()
	raw, err := tcp.SyscallConn()
	if err != nil {
		return true, err
	}
	n := 0
	var readErr syscall.Errno
	err = raw.Read(func(fd uintptr) bool {
		for {
			k, _, e := syscall.Syscall(syscall.SYS_READV, fd, uintptr(unsafe.Pointer(&vectors[0])), uintptr(got))
			if e == syscall.EINTR {
				continue
			}
			readErr = e
			if e == 0 {
				n = int(k)
			}
			// Read only what is ready NOW, never wait for a full vector or hold these
			// leases while waiting for data. EAGAIN returns to the ordinary Read path.
			return true
		}
	})
	if err != nil {
		return true, err
	}
	if readErr == syscall.EAGAIN || readErr == syscall.EWOULDBLOCK {
		return false, nil
	}
	if readErr != 0 {
		return true, readErr
	}
	if n == 0 {
		return true, io.EOF
	}
	if a, ok := src.(*activityStream); ok {
		a.last.Store(time.Now().UnixNano())
	}
	var wires [ss2022BatchRecords][]byte
	used, total := 0, n
	for i := 0; n > 0 && i < got; i++ {
		size := min(n, int(vectors[i].Len))
		n -= size
		wires[used] = buffers[i][:18+size+16]
		used++
	}
	nw, ew := codec.Write2022Buffers(wires[:used])
	m.add(nw)
	if last != nil && nw > 0 {
		last.last.Store(time.Now().UnixNano())
	}
	if ew == nil && nw != total {
		ew = io.ErrShortWrite
	}
	return true, ew
}
