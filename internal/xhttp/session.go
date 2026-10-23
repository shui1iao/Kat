package xhttp

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

type packet struct {
	accounted    bool
	data         []byte
	offset, cost int
	ready        bool
}
type session struct {
	bodyMu                                  sync.Mutex
	bodyWG                                  sync.WaitGroup
	bodyAlive, inputEOF                     bool
	server                                  *Server
	id, owner, mode                         string
	ctx                                     context.Context
	cancel                                  context.CancelCauseFunc
	mu                                      sync.Mutex
	changed                                 chan struct{}
	closed, down, up                        bool
	created, last                           time.Time
	packets                                 map[uint64]*packet
	next                                    uint64
	bufferedPackets, bufferedBytes, uploads int
	uploaded                                int64
	body                                    io.ReadCloser
	bodyRC                                  *http.ResponseController
	uploadDone                              chan struct{}
	uploadOnce                              sync.Once
	readDeadline                            time.Time
	totalBudget                             int64
}

func (ss *session) notify() { close(ss.changed); ss.changed = make(chan struct{}) }
func (s *Server) getSession(id, owner string) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireRetired(time.Now())
	if s.stopped {
		return nil, ErrClosed
	}
	if _, exists := s.retired[id]; exists {
		return nil, ErrAssociation
	}
	if ss := s.sessions[id]; ss != nil {
		if ss.owner != owner {
			return nil, ErrAssociation
		}
		return ss, nil
	}
	if len(s.sessions) >= s.cfg.MaxSessions || len(s.retired)+len(s.sessions) >= s.cfg.MaxRetired {
		return nil, ErrLimit
	}
	unpaired := 0
	for _, ss := range s.sessions {
		ss.mu.Lock()
		if !ss.down || !ss.up {
			unpaired++
		}
		ss.mu.Unlock()
	}
	if unpaired >= s.cfg.MaxUnpaired {
		return nil, ErrLimit
	}
	ctx, cancel := context.WithCancelCause(s.ctx)
	ss := &session{server: s, id: id, owner: owner, ctx: ctx, cancel: cancel, created: time.Now(), last: time.Now(), changed: make(chan struct{}), packets: make(map[uint64]*packet), uploadDone: make(chan struct{})}
	s.sessions[id] = ss
	return ss, nil
}
func (ss *session) close(err error) {
	s := ss.server
	s.mu.Lock()
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		s.mu.Unlock()
		return
	}
	ss.closed = true
	ss.cancel(err)
	for _, p := range ss.packets {
		if p.ready && p.accounted {
			s.bufferedBytes -= p.cost
			s.bufferedPackets--
			ss.bufferedBytes -= p.cost
			ss.bufferedPackets--
			p.accounted = false
		}
	}
	// In-flight request allocations remain charged until that handler returns.

	ss.packets = nil
	delete(s.sessions, ss.id)
	s.retired[ss.id] = time.Now().Add(s.cfg.RetiredTTL)
	ss.notify()
	s.notify()
	ss.mu.Unlock()
	s.mu.Unlock()
	ss.interruptBody()
	ss.uploadOnce.Do(func() { close(ss.uploadDone) })
}
func (ss *session) setMode(mode string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.closed {
		return ErrClosed
	}
	if ss.mode != "" && ss.mode != mode {
		return ErrProtocol
	}
	if ss.server.cfg.Mode != Auto && ss.server.cfg.Mode != mode {
		return ErrProtocol
	}
	ss.mode = mode
	return nil
}
func (ss *session) reserve(seq uint64, n int) (*packet, error) {
	s := ss.server
	s.mu.Lock()
	defer s.mu.Unlock()
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.closed {
		return nil, ErrClosed
	}
	if ss.mode != "" && ss.mode != PacketUp {
		return nil, ErrProtocol
	}
	if seq < ss.next || seq-ss.next >= uint64(s.cfg.MaxBufferedPackets) {
		return nil, ErrAssociation
	}
	if _, exists := ss.packets[seq]; exists {
		return nil, ErrAssociation
	}
	if ss.bufferedPackets >= s.cfg.MaxBufferedPackets || ss.bufferedBytes+n > s.cfg.MaxBufferedBytes || s.bufferedBytes+n > s.cfg.MaxGlobalBufferedBytes || ss.uploads >= s.cfg.MaxUploads || ss.totalBudget+int64(n) > s.cfg.MaxUploadBytes {
		return nil, ErrLimit
	}
	ss.mode = PacketUp
	ss.up = true
	ss.uploads++
	ss.totalBudget += int64(n)
	p := &packet{cost: n, accounted: true}
	ss.packets[seq] = p
	ss.bufferedPackets++
	ss.bufferedBytes += n
	s.bufferedPackets++
	s.bufferedBytes += n
	ss.last = time.Now()
	ss.notify()
	return p, nil
}
func (ss *session) commit(seq uint64, p *packet, data []byte) error {
	s := ss.server
	s.mu.Lock()
	defer s.mu.Unlock()
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.closed || ss.packets[seq] != p {
		return ErrClosed
	}
	ss.uploaded += int64(len(data))
	p.data = data
	p.ready = true
	ss.last = time.Now()
	ss.notify()
	return nil
}
func (ss *session) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s := ss.server
	for {
		s.mu.Lock()
		ss.mu.Lock()
		if ss.closed {
			ss.mu.Unlock()
			s.mu.Unlock()
			return 0, context.Cause(ss.ctx)
		}
		if p := ss.packets[ss.next]; p != nil && p.ready {
			n := copy(b, p.data[p.offset:])
			p.offset += n
			if p.offset == len(p.data) {
				delete(ss.packets, ss.next)
				p.accounted = false
				ss.next++
				ss.bufferedPackets--
				ss.bufferedBytes -= p.cost
				s.bufferedPackets--
				s.bufferedBytes -= p.cost
			}
			ss.last = time.Now()
			ss.notify()
			ss.mu.Unlock()
			s.mu.Unlock()
			if n > 0 {
				return n, nil
			}
			continue
		}
		eof := ss.inputEOF
		deadline := ss.readDeadline
		changed := ss.changed
		ss.mu.Unlock()
		s.mu.Unlock()
		if eof {
			return 0, io.EOF
		}
		if n, e, used := ss.readBody(b, deadline); used {
			return n, e
		}

		timeout := s.cfg.IdleTimeout
		if !deadline.IsZero() && time.Until(deadline) < timeout {
			timeout = time.Until(deadline)
		}
		timer := time.NewTimer(timeout)
		select {
		case <-changed:
			timer.Stop()
		case <-ss.ctx.Done():
			timer.Stop()
			return 0, context.Cause(ss.ctx)
		case <-timer.C:
			ss.close(context.DeadlineExceeded)
			return 0, context.DeadlineExceeded
		}
	}
}

func (ss *session) abortPending(p *packet) {
	s := ss.server
	s.mu.Lock()
	ss.mu.Lock()
	if p.accounted && !p.ready {
		p.accounted = false
		ss.bufferedBytes -= p.cost
		ss.bufferedPackets--
		s.bufferedBytes -= p.cost
		s.bufferedPackets--
		ss.notify()
		s.notify()
	}
	ss.mu.Unlock()
	s.mu.Unlock()
}
