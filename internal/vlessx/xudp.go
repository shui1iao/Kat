package vlessx

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
)

// Mux is UDP-only Mux.Cool/XUDP, not SagerNet smux. No worker goroutine or
// queue is created: core pulls events and applies its own bounded dispatch.
type Mux struct {
	generation               uint64
	rw                       io.ReadWriteCloser
	readMu, writeMu, stateMu sync.Mutex
	sessions                 map[uint16]*muxSession
	max                      int
	closed                   bool
}
type muxSession struct {
	target     Address
	global     [8]byte
	generation uint64
}
type Datagram struct {
	SessionID  uint16
	Target     Address
	Payload    []byte
	GlobalID   [8]byte
	Generation uint64
}

func NewMux(rw io.ReadWriteCloser, maxSessions int) (*Mux, error) {
	if rw == nil || maxSessions < 1 || maxSessions > 1024 {
		return nil, ErrLimit
	}
	return &Mux{rw: rw, max: maxSessions, sessions: map[uint16]*muxSession{}}, nil
}
func (m *Mux) Close() error {
	err := m.rw.Close()
	m.stateMu.Lock()
	m.closed = true
	clear(m.sessions)
	m.stateMu.Unlock()
	return err
}
func (m *Mux) ReadDatagram() (Datagram, error) {
	m.readMu.Lock()
	defer m.readMu.Unlock()
	for control := 0; control < 128; control++ {
		var prefix [2]byte
		if _, e := io.ReadFull(m.rw, prefix[:]); e != nil {
			return Datagram{}, e
		}
		l := int(binary.BigEndian.Uint16(prefix[:]))
		if l < 4 || l > 512 {
			m.Close()
			return Datagram{}, ErrLimit
		}
		h := make([]byte, l)
		if _, e := io.ReadFull(m.rw, h); e != nil {
			m.Close()
			return Datagram{}, e
		}
		id := binary.BigEndian.Uint16(h)
		status, option := h[2], h[3]
		if option&^byte(3) != 0 || status < 1 || status > 4 {
			m.Close()
			return Datagram{}, ErrWire
		}
		var data []byte
		if option&1 != 0 {
			if _, e := io.ReadFull(m.rw, prefix[:]); e != nil {
				m.Close()
				return Datagram{}, e
			}
			n := int(binary.BigEndian.Uint16(prefix[:]))
			if n > 8192 {
				m.Close()
				return Datagram{}, ErrLimit
			}
			data = make([]byte, n)
			if _, e := io.ReadFull(m.rw, data); e != nil {
				m.Close()
				return Datagram{}, e
			}
		}
		var target Address
		var global [8]byte
		hasTarget := false
		if status == 1 || (status == 2 && l > 4) {
			if l < 8 || h[4] != 2 {
				m.Close()
				return Datagram{}, ErrUnsupported
			}
			b := bytes.NewReader(h[5:])
			var e error
			target, e = readAddress(b)
			if e != nil {
				m.Close()
				return Datagram{}, e
			}
			hasTarget = true
			if status == 1 {
				if b.Len() != 0 && b.Len() != 8 {
					m.Close()
					return Datagram{}, ErrWire
				}
				if b.Len() == 8 {
					io.ReadFull(b, global[:])
				}
			} else if b.Len() != 0 {
				m.Close()
				return Datagram{}, ErrWire
			}
		} else if l != 4 {
			m.Close()
			return Datagram{}, ErrWire
		}
		m.stateMu.Lock()
		if m.closed {
			m.stateMu.Unlock()
			return Datagram{}, io.ErrClosedPipe
		}
		s, exists := m.sessions[id]
		if status == 4 {
			m.stateMu.Unlock()
			continue
		}
		if status == 3 {
			if !exists {
				m.stateMu.Unlock()
				m.Close()
				return Datagram{}, ErrState
			}
			delete(m.sessions, id)
			m.stateMu.Unlock()
			continue
		}
		if status == 1 {
			if exists || len(m.sessions) >= m.max {
				m.stateMu.Unlock()
				m.Close()
				return Datagram{}, ErrLimit
			}
			m.generation++
			s = &muxSession{target: target, global: global, generation: m.generation}
			m.sessions[id] = s
		} else if !exists {
			m.stateMu.Unlock()
			m.Close()
			return Datagram{}, ErrState
		}
		if option&2 != 0 {
			delete(m.sessions, id)
			m.stateMu.Unlock()
			continue
		}
		if hasTarget {
			s.target = target
		}
		d := Datagram{SessionID: id, Target: s.target, Payload: data, GlobalID: s.global, Generation: s.generation}
		m.stateMu.Unlock()
		if option&1 != 0 {
			return d, nil
		}
	}
	m.Close()
	return Datagram{}, ErrLimit
}

// Reply preserves Mux session identity and emits each source address explicitly.
// GlobalID is retained metadata, not authorization and not a cross-connection
// reattachment key: this library never trusts a global ID from another session.
func (m *Mux) Reply(d Datagram, source Address, p []byte) error {
	if len(p) > 8192 {
		return ErrLimit
	}
	addr, e := encodeAddress(source)
	if e != nil {
		return e
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.stateMu.Lock()
	s, ok := m.sessions[d.SessionID]
	valid := ok && s.generation == d.Generation && !m.closed
	if !valid {
		m.stateMu.Unlock()
		return ErrState
	}
	h := []byte{byte(d.SessionID >> 8), byte(d.SessionID), 2, 1, 2}
	h = append(h, addr...)
	b := []byte{byte(len(h) >> 8), byte(len(h))}
	b = append(b, h...)
	b = append(b, byte(len(p)>>8), byte(len(p)))
	b = append(b, p...)
	e = writeFull(m.rw, b)
	m.stateMu.Unlock()
	if e != nil {
		m.Close()
	}
	return e
}
func (m *Mux) End(id uint16) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.stateMu.Lock()
	_, ok := m.sessions[id]
	delete(m.sessions, id)
	m.stateMu.Unlock()
	if !ok {
		return ErrState
	}
	return writeFull(m.rw, []byte{0, 4, byte(id >> 8), byte(id), 3, 0})
}
