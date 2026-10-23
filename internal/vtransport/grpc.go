package vtransport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

func (s *Server) grpc(w http.ResponseWriter, r *http.Request, h Handler) {
	mode := ""
	if s.cfg.EnableTun && r.URL.Path == "/"+s.cfg.ServiceName+"/Tun" {
		mode = "Tun"
	}
	if s.cfg.EnableTunMulti && r.URL.Path == "/"+s.cfg.ServiceName+"/TunMulti" {
		mode = "TunMulti"
	}
	if mode == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost || r.ProtoMajor != 2 || !(r.Header.Get("Content-Type") == "application/grpc" || strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc+")) {
		http.Error(w, "HTTP/2 gRPC required", 400)
		return
	}
	if enc := r.Header.Get("Grpc-Encoding"); enc != "" && enc != "identity" {
		http.Error(w, "compression unsupported", 415)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	rc := http.NewResponseController(w)
	reader := &grpcReader{r: r.Body, max: s.cfg.MaxMessageBytes, fields: s.cfg.MaxProtoFields, multi: mode == "TunMulti"}
	writer := &grpcWriter{w: w, controller: rc, timeout: s.cfg.IOTimeout, chunk: s.cfg.WriteChunkBytes}
	st := &Stream{ctx: ctx, cancel: cancel, r: reader, w: writer, closer: r.Body.Close, rd: rc.SetReadDeadline, wd: writer.SetDeadline, flush: rc.Flush}
	if !s.admit(st) {
		cancel()
		http.Error(w, "stream capacity", 503)
		return
	}
	defer s.finish(st)
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(200)
	if e := rc.Flush(); e != nil {
		return
	}
	err := h(ctx, st, Metadata{Kind: GRPC, Path: r.URL.Path, Host: r.Host, Mode: mode, RemoteAddr: r.RemoteAddr})
	status := "0"
	if err != nil {
		status = "13"
	}
	w.Header().Set("Grpc-Status", status)
	// Do not expose VLESS credentials or arbitrary handler error text in trailers.
	if err != nil {
		w.Header().Set("Grpc-Message", "transport%20handler%20failed")
	}
}

type grpcReader struct {
	r           io.Reader
	max, fields int
	multi       bool
	message     []byte
	spans       [][]byte
	err         error
}

func (r *grpcReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for empty := 0; len(r.spans) == 0; empty++ {
		if r.err != nil {
			return 0, r.err
		}
		if empty >= 32 {
			r.err = fmt.Errorf("%w: empty messages", ErrLimit)
			return 0, r.err
		}
		var header [5]byte
		_, e := io.ReadFull(r.r, header[:])
		if e != nil {
			r.err = e
			return 0, e
		}
		size := binary.BigEndian.Uint32(header[1:])
		if header[0] != 0 || size > uint32(r.max) {
			r.err = ErrProtocol
			return 0, r.err
		}
		r.message = make([]byte, int(size))
		if _, e = io.ReadFull(r.r, r.message); e != nil {
			if e == io.EOF {
				e = io.ErrUnexpectedEOF
			}
			r.err = e
			return 0, e
		}
		r.spans, e = parseHunks(r.message, r.multi, r.fields)
		if e != nil {
			r.err = e
			return 0, e
		}
	}
	n := copy(p, r.spans[0])
	r.spans[0] = r.spans[0][n:]
	if len(r.spans[0]) == 0 {
		r.spans[0] = nil
		r.spans = r.spans[1:]
		if len(r.spans) == 0 {
			r.message = nil
		}
	}
	return n, nil
}

// This is only the protobuf wire layout for Hunk {bytes data=1} and MultiHunk
// {repeated bytes data=1}, not a generic protobuf implementation. Unknown legal
// fields are bounded/skipped; singular data follows protobuf last-value-wins.
func parseHunks(b []byte, multi bool, maxFields int) ([][]byte, error) {
	var spans [][]byte
	fields := 0
	for len(b) > 0 {
		fields++
		if fields > maxFields {
			return nil, ErrLimit
		}
		tag, n := binary.Uvarint(b)
		if n <= 0 || tag>>3 == 0 || tag>>3 > 0x1fffffff {
			return nil, ErrProtocol
		}
		b = b[n:]
		number, typ := tag>>3, tag&7
		switch typ {
		case 0:
			_, n = binary.Uvarint(b)
			if n <= 0 {
				return nil, ErrProtocol
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, ErrProtocol
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return nil, ErrProtocol
			}
			b = b[4:]
		case 2:
			size, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, ErrProtocol
			}
			b = b[n:]
			if size > uint64(len(b)) {
				return nil, ErrProtocol
			}
			v := b[:int(size)]
			b = b[int(size):]
			if number == 1 {
				if !multi {
					spans = nil
				}
				if len(v) > 0 {
					spans = append(spans, v)
				}
			}
		default:
			return nil, ErrProtocol
		}
		if number == 1 && typ != 2 {
			return nil, ErrProtocol
		}
	}
	return spans, nil
}

type grpcWriter struct {
	w          io.Writer
	controller *http.ResponseController
	timeout    time.Duration
	chunk      int
	deadline   time.Time
	mu         sync.Mutex
}

func (w *grpcWriter) SetDeadline(t time.Time) error {
	w.mu.Lock()
	w.deadline = t
	w.mu.Unlock()
	return w.controller.SetWriteDeadline(t)
}
func (w *grpcWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), w.chunk)
		body := []byte{0x0a}
		body = binary.AppendUvarint(body, uint64(n))
		body = append(body, p[:n]...)
		wire := []byte{0}
		wire = binary.BigEndian.AppendUint32(wire, uint32(len(body)))
		wire = append(wire, body...)
		w.mu.Lock()
		end := time.Now().Add(w.timeout)
		if !w.deadline.IsZero() && w.deadline.Before(end) {
			end = w.deadline
		}
		w.mu.Unlock()
		if e := w.controller.SetWriteDeadline(end); e != nil {
			return total, e
		}
		if e := writeAll(w.w, wire); e != nil {
			return total, e
		}
		if e := w.controller.Flush(); e != nil {
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
