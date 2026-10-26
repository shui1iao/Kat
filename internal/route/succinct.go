package route

import (
	"errors"
	"math/bits"
)

// louds walks the keys of a LOUDS-encoded succinct trie as written by
// sing-box (srs domain matcher) and mihomo (mrs domain set): labelBitmap has,
// for every node in BFS order, one 0 per child edge followed by a 1; labels
// holds the edge bytes in the order of the 0 bits; leaves marks key ends. The
// k-th 0 bit (0-based) leads to node k+1. f receives every stored key.
func louds(leaves, labelBitmap []uint64, labels []byte, maxKeys int, f func(key []byte) error) error {
	getBit := func(bm []uint64, i int) bool {
		w := i >> 6
		return w < len(bm) && bm[w]&(1<<uint(i&63)) != 0
	}
	ones, last := 0, -1
	for wi, w := range labelBitmap {
		ones += bits.OnesCount64(w)
		if w != 0 {
			last = wi<<6 | (63 - bits.LeadingZeros64(w))
		}
	}
	zeros := last + 1 - ones
	if zeros < 0 || ones != zeros+1 || len(labels) != zeros {
		return errors.New("route: malformed succinct trie")
	}
	nodes := ones
	// first[i]: index of node i's first child; cnt[i]: number of children.
	first := make([]int32, nodes)
	cnt := make([]int32, nodes)
	node, child := 0, 1
	for i := 0; i <= last; i++ {
		if getBit(labelBitmap, i) {
			node++
			continue
		}
		if cnt[node] == 0 {
			first[node] = int32(child)
		}
		cnt[node]++
		child++
	}
	if node != nodes || child != nodes {
		return errors.New("route: malformed succinct trie")
	}
	// Iterative DFS with an explicit key buffer.
	type frame struct{ node, next int32 }
	key := make([]byte, 0, 64)
	stack := []frame{{0, 0}}
	keys := 0
	if getBit(leaves, 0) {
		keys++
		if err := f(key); err != nil {
			return err
		}
	}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.next >= cnt[top.node] {
			stack = stack[:len(stack)-1]
			if len(key) > 0 {
				key = key[:len(key)-1]
			}
			continue
		}
		c := first[top.node] + top.next
		top.next++
		if len(stack) > 512 {
			return errors.New("route: succinct trie too deep")
		}
		key = append(key, labels[c-1])
		if getBit(leaves, int(c)) {
			keys++
			if keys > maxKeys {
				return errLimit
			}
			if err := f(key); err != nil {
				return err
			}
		}
		stack = append(stack, frame{c, 0})
	}
	return nil
}

// reverseRunes reverses s rune-wise (keys are stored reversed per rune).
func reverseRunes(b []byte) string {
	r := []rune(string(b))
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
