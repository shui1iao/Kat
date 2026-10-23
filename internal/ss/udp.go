package ss

import (
	"container/heap"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"golang.org/x/crypto/chacha20poly1305"
)

// Packet owns its plaintext Payload. It contains no aliases to input or other
// packets. The unexported capability authorizes replies only on the originating
// Server/session. Modifying public metadata does not change the replay state.
type Packet struct {
	Target          Address
	Payload         []byte
	UserID          string
	ClientSessionID uint64
	PacketID        uint64
	owner           *Server
	session         *udpSession
	source          netip.AddrPort
}

// DecodeUDP authenticates, validates headers/time/address, then atomically checks
// and updates the replay window and last authenticated peer. Failed validation
// never creates sessions, advances a window or commits client migration.
// A session is keyed by this Server's key + protocol client-session-ID, not source.
// Source must identify an already received datagram; no DNS/network I/O occurs.
func (s *Server) DecodeUDP(wire []byte, source netip.AddrPort) (*Packet, error) {
	if len(wire) > MaxUDPPacketSize || !source.IsValid() {
		return nil, ErrFormat
	}
	if !s.m.v2022 {
		return s.decode2017(wire, source)
	}
	var plain []byte
	var err error
	var clientID, packetID uint64
	var requestAEAD cipher.AEAD
	if s.m.chacha {
		if len(wire) < 24+16+16+11+5 {
			return nil, ErrFormat
		}
		var e error
		plain, e = s.udpX.Open(nil, wire[:24], wire[24:], nil)
		if e != nil {
			return nil, ErrAuth
		}
		clientID = binary.BigEndian.Uint64(plain[:8])
		packetID = binary.BigEndian.Uint64(plain[8:16])
		plain = plain[16:]
	} else {
		if len(wire) < 16+16+11+5 {
			return nil, ErrFormat
		}
		var header [16]byte
		s.udpHeader.Decrypt(header[:], wire[:16])
		clientID = binary.BigEndian.Uint64(header[:8])
		// The subkey is a pure function of key+clientID, so a live session's AEAD
		// is exactly what derivation would give. Lookup alone authorizes nothing:
		// Open must still authenticate; window/peer commit stays below under mu.
		var a cipher.AEAD
		s.mu.Lock()
		if live := s.udp.entries[clientID]; live != nil {
			a = live.requestAEAD
		}
		s.mu.Unlock()
		if a == nil {
			var e error
			if a, e = s.aead(header[:8]); e != nil {
				return nil, e
			}
		}
		requestAEAD = a
		var e error
		plain, e = a.Open(nil, header[4:16], wire[16:], nil)
		if e != nil {
			return nil, ErrAuth
		}
		packetID = binary.BigEndian.Uint64(header[8:])
	}
	if len(plain) < 11 || plain[0] != 0 {
		return nil, ErrFormat
	}
	stamp := binary.BigEndian.Uint64(plain[1:9])
	if err = checkTime(stamp, s.now()); err != nil {
		return nil, err
	}
	padding := int(binary.BigEndian.Uint16(plain[9:11]))
	start := 11 + padding
	if start > len(plain) {
		return nil, ErrFormat
	}
	target, n, err := ParseAddress(plain[start:])
	if err != nil {
		return nil, fmt.Errorf("%w: UDP address", ErrFormat)
	}
	payload := plain[start+n:]
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if err = checkTime(stamp, now); err != nil {
		return nil, err
	}
	s.udp.expire(now)
	session := s.udp.entries[clientID]
	if session == nil {
		if len(s.udp.entries) >= s.udp.capacity {
			return nil, ErrCapacity
		}
		session = &udpSession{clientID: clientID, index: -1, requestAEAD: requestAEAD}
		// Reserve a random outbound session ID distinct from every live outbound ID
		// and from this client ID; never silently reuse nonces on RNG collisions.
		found := false
		for i := 0; i < 8; i++ {
			id, e := s.randomBytes(8)
			if e != nil {
				return nil, e
			}
			v := binary.BigEndian.Uint64(id)
			if v != clientID && !s.udp.serverIDs[v] {
				session.serverID = v
				found = true
				break
			}
		}
		if !found {
			return nil, ErrReplay
		}
		if !s.m.chacha {
			var id [8]byte
			binary.BigEndian.PutUint64(id[:], session.serverID)
			session.responseAEAD, err = s.aead(id[:])
			if err != nil {
				return nil, err
			}
		}
		session.window.accept(packetID)
		session.peer = source
		session.expires = now.Add(replayTTL)
		s.udp.entries[clientID] = session
		s.udp.serverIDs[session.serverID] = true
		heap.Push(&s.udp.queue, session)
	} else {
		if !session.window.accept(packetID) {
			return nil, ErrReplay
		}
		session.peer = source
		s.udp.touch(session, now)
	}
	return &Packet{Target: target, Payload: payload, UserID: s.user, ClientSessionID: clientID, PacketID: packetID, owner: s, session: session, source: source}, nil
}

func (s *Server) decode2017(wire []byte, source netip.AddrPort) (*Packet, error) {
	size := s.m.keySize
	if len(wire) < size+16+5 {
		return nil, ErrFormat
	}
	salt := wire[:size]
	a, err := s.aead2017UDP(salt)
	if err != nil {
		return nil, err
	}
	plain, err := a.Open(nil, make([]byte, 12), wire[size:], nil)
	if err != nil {
		return nil, ErrAuth
	}
	target, n, err := ParseAddress(plain)
	if err != nil {
		return nil, fmt.Errorf("%w: UDP address", ErrFormat)
	}
	s.mu.Lock()
	err = s.oldSalts.admit(salt, s.now())
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &Packet{Target: target, Payload: plain[n:], UserID: s.user, owner: s, source: source}, nil
}

// EncodeUDP makes a server-to-client response with a source address (from) and
// caller-owned payload. The returned ciphertext is independently owned. For 2022
// it binds the response to the authenticated client session and uses the latest
// authenticated peer, even when replying using an older Packet. There is no
// source-address argument capable of bypassing authenticated migration state.
// Expired sessions/capacity/packet-counter exhaustion fail closed.
func (s *Server) EncodeUDP(request *Packet, from Address, payload []byte) (wire []byte, peer netip.AddrPort, err error) {
	if request == nil || request.owner != s {
		return nil, peer, ErrSessionExpired
	}
	if len(payload) > MaxUDPPacketSize {
		return nil, peer, ErrFormat
	}
	address, err := from.MarshalBinary()
	if err != nil {
		return nil, peer, err
	}
	if !s.m.v2022 {
		if s.m.keySize+16+len(address)+len(payload) > MaxUDPPacketSize {
			return nil, peer, ErrFormat
		}
		salt, e := s.responseSalt()
		if e != nil {
			return nil, peer, e
		}
		a, e := s.aead2017UDP(salt)
		if e != nil {
			return nil, peer, e
		}
		// One exact owned wire, rather than body + Seal output + append copy.
		// AEAD supports the exact in-place plaintext/ciphertext overlap here.
		start := len(salt)
		wire = make([]byte, start+len(address)+len(payload)+a.Overhead())
		copy(wire, salt)
		copy(wire[start:], address)
		copy(wire[start+len(address):], payload)
		var nonce [12]byte
		wire = a.Seal(wire[:start], nonce[:], wire[start:len(wire)-a.Overhead()], nil)
		return wire, request.source, nil
	}
	overhead := 16 + 16 + 19
	if s.m.chacha {
		overhead = 24 + 16 + 16 + 19
	}
	if overhead+len(address)+len(payload) > MaxUDPPacketSize {
		return nil, peer, ErrFormat
	}
	var nonce []byte
	if s.m.chacha {
		if nonce, err = s.randomBytes(24); err != nil {
			return nil, peer, err
		}
	}
	// Under the codec lock only: session liveness/expiry, exhaustion, and the
	// unique response packet-ID reservation plus a snapshot of the latest
	// authenticated peer. Sealing uses only immutable per-session/per-Server
	// AEADs and the reserved header, so it runs outside the lock (0.5.20).
	s.mu.Lock()
	now := s.now()
	s.udp.expire(now)
	session := request.session
	if session == nil || s.udp.entries[session.clientID] != session {
		s.mu.Unlock()
		return nil, peer, ErrSessionExpired
	}
	if session.exhausted {
		s.mu.Unlock()
		return nil, peer, ErrNonceExhausted
	}
	if now.Unix() < 0 {
		s.mu.Unlock()
		return nil, peer, ErrTimestamp
	}
	var header [16]byte
	binary.BigEndian.PutUint64(header[:8], session.serverID)
	binary.BigEndian.PutUint64(header[8:], session.nextPacket)
	if session.nextPacket == math.MaxUint64 {
		session.exhausted = true
	} else {
		session.nextPacket++
	}
	clientID, responseAEAD := session.clientID, session.responseAEAD
	// Outgoing traffic does not extend authenticated incoming session lifetime.
	peer = session.peer
	s.mu.Unlock()
	// One exact owned wire; AEAD seals the body in place (exact overlap).
	bodyLen := 19 + len(address) + len(payload)
	fill := func(b []byte) {
		b[0] = 1
		binary.BigEndian.PutUint64(b[1:9], uint64(now.Unix()))
		binary.BigEndian.PutUint64(b[9:17], clientID)
		b[17], b[18] = 0, 0
		copy(b[19:], address)
		copy(b[19+len(address):], payload)
	}
	if s.m.chacha {
		wire = make([]byte, 24+16+bodyLen+s.udpX.Overhead())
		copy(wire, nonce)
		plain := wire[24 : 24+16+bodyLen]
		copy(plain, header[:])
		fill(plain[16:])
		return s.udpX.Seal(wire[:24], nonce, plain, nil), peer, nil
	}
	wire = make([]byte, 16+bodyLen+responseAEAD.Overhead())
	s.udpHeader.Encrypt(wire[:16], header[:])
	body := wire[16 : 16+bodyLen]
	fill(body)
	return responseAEAD.Seal(wire[:16], header[4:16], body, nil), peer, nil
}

// UDP-only fixed-length HKDF is the same RFC5869/SIP004 SHA1 extraction/expansion
// as deriveAEAD, without generic hash.Hash/HMAC/Reader allocations.
// TCP and SS2022 keep their original derivation paths. Cipher constructors copy
// the key; clear the temporary material immediately after construction.
func (s *Server) aead2017UDP(salt []byte) (cipher.AEAD, error) {
	if (len(s.key) != 16 && len(s.key) != 32) || len(salt) != s.m.keySize {
		return nil, ErrKey
	}
	var material [32]byte
	sub := material[:s.m.keySize]
	udp2017Subkey(s.key, salt, sub)
	defer clear(material[:])
	if s.m.chacha {
		return chacha20poly1305.New(sub)
	}
	block, e := aes.NewCipher(sub)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
