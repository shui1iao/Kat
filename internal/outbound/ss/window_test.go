package ss

import "testing"

func TestWindow(t *testing.T) {
	var w window
	for _, c := range []struct {
		id uint64
		ok bool
	}{{5, true}, {5, false}, {3, true}, {3, false}, {4, true}, {6, true}, {1030, true}, {6, false}, {7, true}, {7, false}, {5000, true}, {3900, false}, {4000, true}, {4000, false}, {4999, true}} {
		if got := w.accept(c.id); got != c.ok {
			t.Fatalf("accept(%d)=%v want %v", c.id, got, c.ok)
		}
	}
}
