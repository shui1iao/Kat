package anytls

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Request is delivered only after password authentication, settings and complete
// target parsing. UDP is nonnil for the UoT v2 magic destination. Target then is
// the UoT initial destination (fixed in connected mode, advisory otherwise).
type Request struct {
	UserID   string
	StreamID uint32
	Version  int
	Target   Address
	UDP      *DatagramConn
}

// Handler must return on stream/session cancellation and must not retain work
// after returning. Serve waits for its handlers; Go cannot kill arbitrary code.
type Handler func(context.Context, *Stream, Request)
type outbound struct {
	command      byte
	sendWatchdog bool  // fits existing header padding; no outbound metadata growth
	reusable     bool  // bounded owned-TCP metadata cache, never ordinary Write
	refs         int32 // sender + actual writer; both must release before reuse
	wire         []byte
	stream       *Stream
	done         chan error
	cost         int
	release      func([]byte) // owned TCP-down lease, nil for the unchanged send path
}
type session struct {
	server                                 *Server
	transport                              io.ReadWriteCloser
	ctx                                    context.Context
	cancel                                 context.CancelCauseFunc
	mu                                     sync.Mutex
	change                                 chan struct{}
	readChange                             chan struct{} // one lazy receive-domain broadcast per session
	activeWriter                           *outbound     // protected by mu; only this exact I/O owner may release it
	writerChange                           chan struct{} // capacity1; exactly one writer, coalesced wakeups
	active                                 map[uint32]*Stream
	workers                                map[*Stream]bool
	closed                                 map[uint32]bool
	closedOrder                            []uint32
	lastID                                 uint32
	settings                               bool
	version                                int
	inFrames, inBytes, outFrames, outBytes int
	out                                    []*outbound
	workerWG                               sync.WaitGroup
	writerDone                             chan struct{}
	watchDone                              chan struct{}
	once                                   sync.Once
	pingMu                                 sync.Mutex
	pingAck                                chan struct{}
}
type SessionStats struct {
	Streams, Workers, InboundFrames, InboundBytes, OutboundFrames, OutboundBytes int
	Version                                                                      int
}

// Both helpers are called under mu. Allocate a broadcast channel only when a
// worker will actually wait; uncontended frame processing needs no channel.
func (s *session) notify() {
	if s.change != nil {
		close(s.change)
		s.change = nil
	}
}
func (s *session) waitChange() <-chan struct{} {
	if s.change == nil {
		s.change = make(chan struct{})
	}
	return s.change
}

// Separate data readiness from queue-budget progress. In the old shared
// generation channel, inbound PSH/release woke the empty writer and outbound
// progress woke every empty reader. Neither can make progress on those events.
func (s *session) waitReadChange() <-chan struct{} {
	if s.readChange == nil {
		s.readChange = make(chan struct{})
	}
	return s.readChange
}
func (s *session) notifyRead() {
	if s.readChange != nil {
		close(s.readChange)
		s.readChange = nil
	}
}
func (s *session) waitWriterChange() <-chan struct{} {
	if s.writerChange == nil {
		s.writerChange = make(chan struct{}, 1)
	}
	return s.writerChange
}
func (s *session) notifyWriter() {
	if s.writerChange != nil {
		select {
		case s.writerChange <- struct{}{}:
		default:
		}
	}
}

func (s *session) fail(err error) {
	if err == nil {
		err = io.EOF
	}
	s.once.Do(func() { s.cancel(err); _ = s.transport.Close(); s.mu.Lock(); s.notify(); s.mu.Unlock() })
}
func (s *session) remember(id uint32) {
	if s.closed[id] {
		return
	}
	s.closed[id] = true
	s.closedOrder = append(s.closedOrder, id)
	if len(s.closedOrder) > s.server.cfg.MaxClosedStreams {
		delete(s.closed, s.closedOrder[0])
		s.closedOrder = s.closedOrder[1:]
	}
}

// Serve owns and closes transport on every return. The transport MUST already
// be a secure, handshaken TLS connection with 0-RTT disabled by the caller.
// No TLS handshake/listener, target dial, routing or fallback HTTP is performed.
func (s *Server) Serve(ctx context.Context, transport io.ReadWriteCloser, handler Handler) error {
	if transport == nil || handler == nil {
		return ErrConfig
	}
	s.mu.Lock()
	if s.sessions >= s.cfg.MaxSessions {
		s.mu.Unlock()
		_ = transport.Close()
		return ErrSessionLimit
	}
	s.sessions++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.sessions--; s.mu.Unlock() }()
	child, cancel := context.WithCancelCause(ctx)
	sess := &session{server: s, transport: transport, ctx: child, cancel: cancel, change: make(chan struct{}), active: make(map[uint32]*Stream), workers: make(map[*Stream]bool), closed: make(map[uint32]bool), writerDone: make(chan struct{}), watchDone: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			sess.fail(context.Cause(ctx))
		case <-sess.watchDone:
		}
	}()
	authTimer := time.AfterFunc(s.cfg.HandshakeTimeout, func() { sess.fail(context.DeadlineExceeded) })
	var initial [34]byte
	_, err := io.ReadFull(transport, initial[:])
	if err == nil {
		n := int(binary.BigEndian.Uint16(initial[32:]))
		if n > s.cfg.MaxAuthPadding {
			err = ErrAuthentication
		} else {
			err = discard(transport, n)
		}
	}
	if err == nil && subtle.ConstantTimeCompare(initial[:32], s.digest[:]) != 1 {
		err = ErrAuthentication
	}
	clear(initial[:])
	if err != nil {
		if sess.ctx.Err() != nil {
			err = context.Cause(sess.ctx)
		}
		authTimer.Stop()
		sess.fail(err)
		close(sess.watchDone)
		return err
	}
	go sess.writeLoop()
	err = sess.readLoop(handler, authTimer)
	if sess.ctx.Err() != nil {
		err = context.Cause(sess.ctx)
	}
	authTimer.Stop()
	if err != nil && sess.ctx.Err() == nil && (errors.Is(err, ErrProtocol) || errors.Is(err, ErrStreamLimit) || errors.Is(err, ErrSlowConsumer) || errors.Is(err, ErrQueueLimit)) {
		_ = sess.send(cmdAlert, 0, []byte(err.Error()), nil, time.Time{})
	}
	// Closing the transport unblocks both loops and cancels every logical stream.
	cause := err
	if cause == nil {
		cause = io.EOF
	}
	sess.fail(cause)
	sess.mu.Lock()
	for st := range sess.workers {
		st.closeLocked(cause, false, true)
	}
	sess.notify()
	sess.mu.Unlock()
	<-sess.writerDone
	sess.workerWG.Wait()
	close(sess.watchDone)
	if err == nil && ctx.Err() == nil {
		return nil
	}
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if err == nil {
		return context.Cause(child)
	}
	return err
}
func (s *session) readLoop(handler Handler, authTimer *time.Timer) error {
	var header [7]byte
	for {
		n, e := io.ReadFull(s.transport, header[:])
		if e != nil {
			if e == io.EOF && n == 0 {
				s.mu.Lock()
				idle := len(s.active) == 0
				s.mu.Unlock()
				if idle {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return e
		}
		command := header[0]
		id := binary.BigEndian.Uint32(header[1:5])
		length := int(binary.BigEndian.Uint16(header[5:7]))
		if length > s.server.cfg.MaxFrameData {
			return fmt.Errorf("%w: frame length", ErrProtocol)
		}
		if command == cmdWaste {
			if e = discard(s.transport, length); e != nil {
				return e
			}
			continue
		}
		if !s.settings && command != cmdSettings {
			return fmt.Errorf("%w: settings required before streams/heartbeat", ErrProtocol)
		}
		switch command {
		case cmdSettings:
			if s.settings || length > s.server.cfg.MaxSettings {
				return fmt.Errorf("%w: settings repeated/oversized", ErrProtocol)
			}
			b := make([]byte, length)
			if _, e = io.ReadFull(s.transport, b); e != nil {
				return unexpected(e)
			}
			v, fp, e := parseSettings(b)
			if e != nil {
				return e
			}
			s.mu.Lock()
			s.settings = true
			s.version = v
			s.mu.Unlock()
			authTimer.Stop()
			if v >= 2 {
				if e = s.send(cmdServerSettings, 0, []byte("v=2"), nil, time.Time{}); e != nil {
					return e
				}
			}
			if fp != s.server.paddingMD5 {
				if e = s.send(cmdPadding, 0, []byte(s.server.cfg.PaddingScheme), nil, time.Time{}); e != nil {
					return e
				}
			}
		case cmdSYN:
			if length != 0 || id == 0 {
				return fmt.Errorf("%w: SYN body/zero ID", ErrProtocol)
			}
			st, e := s.newStream(id)
			if e != nil {
				if !errors.Is(e, ErrStreamLimit) {
					return e
				}
				if s.version >= 2 {
					e = s.send(cmdSYNACK, id, []byte(ErrStreamLimit.Error()), nil, time.Time{})
				} else {
					e = s.send(cmdFIN, id, nil, nil, time.Time{})
				}
				if e != nil {
					return e
				}
				continue
			}
			go s.prepare(st, handler)
			// Explicitly permitted optimistic SYNACK: protocol admission, not dial success.
			if s.version >= 2 {
				if e = s.send(cmdSYNACK, id, nil, nil, time.Time{}); e != nil {
					return e
				}
			}
		case cmdPSH:
			if id == 0 {
				return fmt.Errorf("%w: zero stream ID", ErrProtocol)
			}
			s.mu.Lock()
			st := s.active[id]
			retired := s.closed[id]
			s.mu.Unlock()
			if st == nil {
				if !retired {
					return fmt.Errorf("%w: PSH for unknown stream", ErrProtocol)
				}
				if e = discard(s.transport, length); e != nil {
					return e
				}
				continue
			}
			if length == 0 {
				continue
			}
			if e = s.reserveInbound(st, length); e != nil {
				if errors.Is(e, ErrStreamClosed) {
					if e = discard(s.transport, length); e != nil {
						return e
					}
					continue
				}
				return e
			}
			b := takeInboundFrame(length)
			_, e = io.ReadFull(s.transport, b)
			s.publishInbound(st, b, e)
			if e != nil {
				return unexpected(e)
			}
		case cmdFIN:
			if length != 0 || id == 0 {
				return fmt.Errorf("%w: FIN data/ID", ErrProtocol)
			}
			s.mu.Lock()
			st := s.active[id]
			retired := s.closed[id]
			if st != nil {
				st.closeLocked(io.EOF, true, false)
			}
			s.mu.Unlock()
			if st == nil && !retired {
				return fmt.Errorf("%w: FIN for unknown stream", ErrProtocol)
			}
		case cmdHeartRequest, cmdHeartResponse:
			if s.version < 2 || length != 0 {
				return fmt.Errorf("%w: heartbeat version/body", ErrProtocol)
			}
			if command == cmdHeartRequest {
				if e = s.send(cmdHeartResponse, id, nil, nil, time.Time{}); e != nil {
					return e
				}
			} else {
				s.mu.Lock()
				if s.pingAck != nil {
					close(s.pingAck)
					s.pingAck = nil
				}
				s.mu.Unlock()
			}
		default:
			return fmt.Errorf("%w: illegal client command %d", ErrProtocol, command)
		}
	}
}
func unexpected(e error) error {
	if e == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return e
}
func (s *session) newStream(id uint32) (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id <= s.lastID {
		return nil, fmt.Errorf("%w: nonmonotonic/duplicate SYN", ErrProtocol)
	}
	s.lastID = id
	s.server.mu.Lock()
	limited := len(s.workers) >= s.server.cfg.MaxStreams || s.server.streams >= s.server.cfg.MaxTotalStreams
	if limited {
		s.server.mu.Unlock()
		s.remember(id)
		return nil, ErrStreamLimit
	}
	s.server.streams++
	s.server.mu.Unlock()
	ctx, cancel := context.WithCancelCause(s.ctx)
	st := &Stream{session: s, id: id, ctx: ctx, cancel: cancel}
	s.active[id] = st
	s.workers[st] = true
	s.workerWG.Add(1)
	return st, nil
}
func (s *session) prepare(st *Stream, handler Handler) {
	defer func() {
		_ = st.Close()
		s.mu.Lock()
		delete(s.workers, st)
		s.notify()
		s.mu.Unlock()
		s.server.mu.Lock()
		s.server.streams--
		s.server.mu.Unlock()
		s.workerWG.Done()
	}()
	_ = st.SetReadDeadline(time.Now().Add(s.server.cfg.TargetTimeout))
	target, e := readAddress(st, false)
	if e != nil {
		return
	}
	request := Request{UserID: s.server.cfg.UserID, StreamID: st.id, Version: s.version, Target: target}
	if target.Host == MagicUDPHost {
		udp, e := newDatagram(st)
		if e != nil {
			return
		}
		request.UDP = udp
		request.Target = udp.target
	}
	_ = st.SetReadDeadline(time.Time{})
	if st.ctx.Err() != nil {
		return
	}
	handler(st.ctx, st, request)
}
func (s *session) reserveInbound(st *Stream, n int) error {
	cost := n + 7
	c := s.server.cfg
	if cost > c.StreamInboundBytes || cost > c.SessionInboundBytes {
		return ErrQueueLimit
	}
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		s.mu.Lock()
		if st.closed {
			s.mu.Unlock()
			return ErrStreamClosed
		}
		if st.inFrames < c.StreamInboundFrames && st.inBytes+cost <= c.StreamInboundBytes && s.inFrames < c.SessionInboundFrames && s.inBytes+cost <= c.SessionInboundBytes {
			st.inFrames++
			st.inBytes += cost
			st.reservedFrames++
			st.reservedBytes += cost
			s.inFrames++
			s.inBytes += cost
			s.mu.Unlock()
			return nil
		}
		ch := s.waitChange()
		if timer == nil {
			timer = time.NewTimer(c.SlowConsumerTimeout)
		}
		s.mu.Unlock()
		select {
		case <-ch:
		case <-s.ctx.Done():
			return context.Cause(s.ctx)
		case <-st.ctx.Done():
			return ErrStreamClosed
		case <-timer.C:
			return ErrSlowConsumer
		}
	}
}
func (s *session) publishInbound(st *Stream, b []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cost := len(b) + 7
	st.reservedFrames--
	st.reservedBytes -= cost
	if err != nil || st.closed {
		// The reservation still owns the entire exact-capacity backing allocation.
		releaseInboundFrame(b)
		st.inFrames--
		st.inBytes -= cost
		s.inFrames--
		s.inBytes -= cost
		s.notify() // a rejected reservation actually frees budget
	} else {
		st.input = append(st.input, b)
	}
	s.notifyRead()
}

// outboundLease transfers one fully charged allocation to the writer. The
// sender may time out before transport I/O returns, so only the writer (or
// queue teardown) may clear/release an enqueued lease.
type outboundLease struct {
	wire    []byte
	release func([]byte)
}

func disposeOutboundWire(wire []byte, release func([]byte)) {
	clear(wire[:cap(wire)])
	if release != nil {
		release(wire)
	}
}

func (s *session) send(command byte, id uint32, data []byte, st *Stream, deadline time.Time, lease ...outboundLease) (result error) {
	var provided []byte
	var release func([]byte)
	if len(lease) != 0 {
		provided, release = lease[0].wire, lease[0].release
		defer func() {
			if provided != nil {
				disposeOutboundWire(provided, release)
			}
		}()
	}
	c := s.server.cfg
	cost := len(data) + 7
	if provided != nil {
		cost = cap(provided)
	}
	if len(data) > 65535 || cost > c.SessionOutboundBytes || (st != nil && cost > c.StreamOutboundBytes) {
		return ErrQueueLimit
	}
	end := time.Now().Add(c.WriteTimeout)
	if !deadline.IsZero() && deadline.Before(end) {
		end = deadline
	}
	// Owned TCP-down sends already wait for completion under a serialized
	// stream writer. One absolute AfterFunc protects queue + in-flight I/O,
	// instead of both a caller NewTimer and a second writer AfterFunc. Ordinary
	// Write/control/UoT retain their existing timer and writer watchdog path.
	ownedWatchdog := provided != nil
	var senderFrame *outbound
	var timer *time.Timer
	var timeout <-chan time.Time
	if ownedWatchdog {
		ownedTimer := acquireOwnedWriteTimer(s, end)
		defer func() {
			if !stopOwnedWriteTimer(ownedTimer) {
				s.fail(ErrWriteTimeout)
				if result == nil {
					result = ErrWriteTimeout
				}
			}
			if senderFrame != nil {
				releaseOwnedMetadata(senderFrame)
			}
		}()
	} else {
		timer = time.NewTimer(time.Until(end))
		timeout = timer.C
		defer timer.Stop()
	}
	for {
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			return context.Cause(s.ctx)
		}
		if st != nil && st.closed {
			s.mu.Unlock()
			return ErrStreamClosed
		}
		available := s.outFrames < c.SessionOutboundFrames && s.outBytes+cost <= c.SessionOutboundBytes && (st == nil || (st.outFrames < c.StreamOutboundFrames && st.outBytes+cost <= c.StreamOutboundBytes))
		if available {
			// Reserve the complete retained frame (payload+7) before allocation.
			// One owned wire replaces the old payload copy plus writer wire copy.
			s.outFrames++
			s.outBytes += cost
			if st != nil {
				st.outFrames++
				st.outBytes += cost
			}
			var owned []byte
			if provided != nil {
				owned, provided = provided, nil
			} else {
				owned = make([]byte, cost)
			}
			owned[0] = command
			binary.BigEndian.PutUint32(owned[1:5], id)
			binary.BigEndian.PutUint16(owned[5:7], uint16(len(data)))
			copy(owned[7:], data)
			var frame *outbound
			if ownedWatchdog {
				frame = takeOwnedMetadata()
				senderFrame = frame
			} else {
				frame = &outbound{done: make(chan error, 1)}
			}
			frame.command = command
			frame.wire = owned
			frame.stream = st
			frame.cost = cost
			frame.release = release
			frame.sendWatchdog = ownedWatchdog
			// Real TLS-over-TCP has a concrete cancellation guarantee: while Write
			// is active, tls.Conn.Close closes its underlying TCPConn and unblocks
			// the write. Generic transports retain the asynchronous late-owner path.
			inline := false
			if ownedWatchdog && s.activeWriter == nil && len(s.out) == 0 {
				if tc, ok := s.transport.(*tls.Conn); ok {
					_, inline = tc.NetConn().(*net.TCPConn)
				}
			}
			if inline {
				s.activeWriter = frame
				s.mu.Unlock()
				e := writeAll(s.transport, frame.wire)
				if e != nil {
					s.fail(e)
				}
				s.releaseOutbound(frame, e)
			} else {
				s.out = append(s.out, frame)
				s.notifyWriter()
				s.mu.Unlock()
			}
			select {
			case err := <-frame.done:
				return err
			case <-s.ctx.Done():
				return context.Cause(s.ctx)
			case <-timeout:
				s.fail(ErrWriteTimeout)
				return ErrWriteTimeout
			}
		}
		ch := s.waitChange()
		s.mu.Unlock()
		select {
		case <-ch:
		case <-s.ctx.Done():
			return context.Cause(s.ctx)
		case <-timeout:
			s.fail(ErrWriteTimeout)
			return ErrWriteTimeout
		}
	}
}
func (s *session) releaseOutbound(f *outbound, err error) {
	s.mu.Lock()
	// Writer owns the backing allocation through I/O; keep it charged until clear.
	disposeOutboundWire(f.wire, f.release)
	f.wire = nil
	f.release = nil
	if s.activeWriter == f {
		s.activeWriter = nil
		if len(s.out) > 0 {
			s.notifyWriter()
		}
	}
	s.outFrames--
	s.outBytes -= f.cost
	if f.stream != nil {
		f.stream.outFrames--
		f.stream.outBytes -= f.cost
	}
	s.notify()
	s.mu.Unlock()
	f.done <- err
	releaseOwnedMetadata(f) // writer owns its reference until after completion publication
}
func (s *session) writeLoop() {
	var watchdog *time.Timer
	defer func() {
		if watchdog != nil {
			watchdog.Stop()
		}
	}()
	defer close(s.writerDone)
	defer func() {
		s.mu.Lock()
		q := s.out
		s.out = nil
		s.mu.Unlock()
		for _, f := range q {
			s.releaseOutbound(f, context.Cause(s.ctx))
		}
	}()
	for {
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		if len(s.out) == 0 || s.activeWriter != nil {
			// Do not retain a timer allocation on an idle session.
			watchdog = nil
			ch := s.waitWriterChange()
			// Queue is empty under mu. Discard a coalesced token from work
			// already processed; no producer can append until we unlock.
			select {
			case <-ch:
			default:
			}
			s.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-s.ctx.Done():
				return
			}
		}
		f := s.out[0]
		s.activeWriter = f
		s.out[0] = nil
		s.out = s.out[1:]
		skip := f.stream != nil && f.stream.closed
		s.mu.Unlock()
		if skip {
			s.releaseOutbound(f, ErrStreamClosed)
			continue
		}
		wire := f.wire
		if f.sendWatchdog {
			// Sender retains its timer through release/full clear. A sender
			// timeout cancels and closes transport but never returns ownership.
			err := writeAll(s.transport, wire)
			s.releaseOutbound(f, err)
			if err != nil {
				s.fail(err)
				return
			}
			continue
		}
		// Reuse only a successfully stopped watchdog for ALREADY queued frames.
		// Stop=false means its callback may run: fail and never reset/reuse it.
		if watchdog == nil {
			watchdog = time.AfterFunc(s.server.cfg.WriteTimeout, func() { s.fail(ErrWriteTimeout) })
		} else {
			watchdog.Reset(s.server.cfg.WriteTimeout)
		}
		err := writeAll(s.transport, wire)
		stopped := watchdog.Stop()
		s.releaseOutbound(f, err)
		if !stopped {
			s.fail(ErrWriteTimeout)
			return
		}
		if err != nil {
			s.fail(err)
			return
		}
	}
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
