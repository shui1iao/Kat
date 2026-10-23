package anytls

import (
	"sync"
	"testing"
	"unsafe"
)

func emptyOwnedCache() {
	for {
		select {
		case <-ownedMetadataFree:
		default:
			return
		}
	}
}
func TestOwnedMetadataLastOwnerAndStaleCompletion(t *testing.T) {
	emptyOwnedCache()
	defer emptyOwnedCache()
	f := takeOwnedMetadata()
	f.wire = []byte("still-owned")
	f.cost = 11
	f.stream = &Stream{}
	f.release = func([]byte) {}
	releaseOwnedMetadata(f)
	if len(ownedMetadataFree) != 0 || string(f.wire) != "still-owned" || f.cost != 11 {
		t.Fatal("first owner prematurely pooled inflight frame")
	}
	// Sender timed out and never read done; writer eventually publishes completion.
	f.done <- ErrWriteTimeout
	releaseOwnedMetadata(f)
	if len(ownedMetadataFree) != 1 {
		t.Fatal("last owner did not return metadata")
	}
	reused := takeOwnedMetadata()
	if reused != f {
		t.Fatal("not reused")
	}
	if reused.wire != nil || reused.stream != nil || reused.release != nil || reused.cost != 0 || reused.sendWatchdog {
		t.Fatal("old session/frame alias retained")
	}
	select {
	case <-reused.done:
		t.Fatal("old timeout poisoned next send")
	default:
	}
	releaseOwnedMetadata(reused)
	releaseOwnedMetadata(reused)
}
func TestOwnedMetadataConcurrentReleaseAndBound(t *testing.T) {
	emptyOwnedCache()
	defer emptyOwnedCache()
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(outbound{}) != 64 {
		t.Fatal("descriptor budget grew", unsafe.Sizeof(outbound{}))
	}
	frames := make([]*outbound, 32)
	for i := range frames {
		frames[i] = takeOwnedMetadata()
		frames[i].done <- nil
	}
	var wg sync.WaitGroup
	for _, f := range frames {
		wg.Add(2)
		go func(f *outbound) { defer wg.Done(); releaseOwnedMetadata(f) }(f)
		go func(f *outbound) { defer wg.Done(); releaseOwnedMetadata(f) }(f)
	}
	wg.Wait()
	if len(ownedMetadataFree) != OwnedMetadataCacheSlots {
		t.Fatal("unbounded/duplicated pooled descriptors", len(ownedMetadataFree))
	}
	seen := map[*outbound]bool{}
	for i := 0; i < OwnedMetadataCacheSlots; i++ {
		f := <-ownedMetadataFree
		if seen[f] {
			t.Fatal("descriptor pooled twice")
		}
		seen[f] = true
		select {
		case <-f.done:
			t.Fatal("undrained completion")
		default:
		}
	}
}
