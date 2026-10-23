package ss

import "crypto/sha1"

// SIP004's exact HKDF-SHA1 for the ONLY supported key/salt lengths16/32.
// Use stdlib SHA1 compression, not custom cryptography or a keyed cache. All
// pads, PRK and intermediate digests are per-call fixed stack buffers and cleared.
// Extract=HMAC(salt,master), T1=HMAC(PRK,info||1), T2=HMAC(PRK,T1||info||2).
// Fixed lengths remove generic hash.Hash/HMAC/io.Reader allocations, not rounds.
func udp2017Subkey(master, salt []byte, out []byte) {
	var block [64 + 32]byte
	var outer [64 + sha1.Size]byte
	var prk, inner, t [sha1.Size]byte
	defer func() { clear(block[:]); clear(outer[:]); clear(prk[:]); clear(inner[:]); clear(t[:]) }()
	for i := 0; i < 64; i++ {
		block[i] = 0x36
		outer[i] = 0x5c
	}
	for i, b := range salt {
		block[i] ^= b
		outer[i] ^= b
	}
	copy(block[64:], master)
	inner = sha1.Sum(block[:64+len(master)])
	copy(outer[64:], inner[:])
	prk = sha1.Sum(outer[:])
	for i := 0; i < 64; i++ {
		block[i] = 0x36
		outer[i] = 0x5c
	}
	for i, b := range prk {
		block[i] ^= b
		outer[i] ^= b
	}
	n := copy(block[64:], "ss-subkey")
	block[64+n] = 1
	inner = sha1.Sum(block[:64+n+1])
	copy(outer[64:], inner[:])
	t = sha1.Sum(outer[:])
	copied := copy(out, t[:])
	if copied < len(out) {
		copy(block[64:], t[:])
		n = copy(block[64+sha1.Size:], "ss-subkey")
		block[64+sha1.Size+n] = 2
		inner = sha1.Sum(block[:64+sha1.Size+n+1])
		copy(outer[64:], inner[:])
		t = sha1.Sum(outer[:])
		copy(out[copied:], t[:])
	}
}
