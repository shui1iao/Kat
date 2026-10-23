package snell

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"math/bits"
)

// shapedPadding independently realizes the observed initial bit-ratio shaping.
// It does not reproduce the official C PRNG or its biased shuffle fingerprint.
func shapedPadding(size int, ciphertext []byte) ([]byte, error) {
	out := make([]byte, size)
	if size == 0 {
		return out, nil
	}
	ones := 0
	for i := 0; i+4 <= len(ciphertext); i += 4 {
		ones += bits.OnesCount32(binary.LittleEndian.Uint32(ciphertext[i : i+4]))
	}
	zeros := 8*len(ciphertext) - ones
	if zeros == 0 {
		return out, fillRandom(out)
	}
	ratio := float64(ones) / float64(zeros)
	if ratio <= 0.5 || ratio >= 1.6 {
		return out, fillRandom(out)
	}
	base := 1.6
	if ones > zeros {
		base = 0.4
	}
	// Uniform 53-bit fraction for an independently implemented 0..0.1 perturbation.
	var entropy [8]byte
	if _, e := rand.Read(entropy[:]); e != nil {
		return nil, e
	}
	target := base + float64(binary.LittleEndian.Uint64(entropy[:])>>11)/(1<<53)*0.1
	selected := int(math.Floor(float64((size+len(ciphertext))*8)*target/(1+target) - float64(ones)))
	if selected < 0 || selected > size*8 {
		return out, fillRandom(out)
	}
	// A partial unbiased Fisher-Yates permutation selects the requested bit count.
	// Runtime and working memory are strictly bounded by size*8 (at most 4088).
	indices := make([]uint16, size*8)
	for i := range indices {
		indices[i] = uint16(i)
	}
	for i := 0; i < selected; i++ {
		n, e := rand.Int(rand.Reader, big.NewInt(int64(len(indices)-i)))
		if e != nil {
			return nil, e
		}
		j := i + int(n.Int64())
		indices[i], indices[j] = indices[j], indices[i]
		bit := indices[i]
		out[bit/8] |= 1 << (bit % 8)
	}
	return out, nil
}
func fillRandom(p []byte) error { _, e := rand.Read(p); return e }
