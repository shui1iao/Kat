package ss

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// A fresh test process has no earlier AddCleanup callbacks. Synthetic budget
// reservations consume accounting ONLY, not2GiB RAM; no production hook needed.
func TestCompactGlobalBudgetAllocationPaths(t *testing.T) {
	mode := os.Getenv("KAT_SS_COMPACT_BUDGET_CHILD")
	if mode == "" {
		for _, m := range []string{"bucket", "entry", "cleanup", "contend"} {
			t.Run(m, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCompactGlobalBudgetAllocationPaths$", "-test.v", "-test.count=1")
				cmd.Env = append(os.Environ(), "KAT_SS_COMPACT_BUDGET_CHILD="+m)
				out, e := cmd.CombinedOutput()
				if e != nil {
					t.Fatalf("%v\n%s", e, out)
				}
				t.Log(string(out))
			})
		}
		return
	}
	if compactRetained.Load() != 0 {
		t.Fatal("child not isolated")
	}
	bucketBytes := int64(unsafe.Sizeof(compactBuckets{}))
	entryBytes := int64(unsafe.Sizeof(compactEntries{}))
	switch mode {
	case "bucket", "entry":
		// In entry mode there is room for exactly one bucket page but NOT an entry.
		fake := compactBudget
		if mode == "entry" {
			fake -= bucketBytes
		}
		if !reserveCompact(fake) {
			t.Fatal("synthetic reservation")
		}
		first := new(compactSaltStore)
		first.init(8)
		second := new(compactSaltStore)
		second.init(8)
		key := compactKey(17, 16)
		if err := first.admit(key, testTime); err != ErrCapacity {
			t.Fatal("did not enter allocation failure", err)
		}
		if first.count != 0 || first.head != 0 || first.tail != 0 || first.keyLen != 0 || !first.epoch.IsZero() {
			t.Fatal("failed insertion changed logical state")
		}
		for _, page := range first.pages {
			if page != nil {
				t.Fatal("entry page allocated without budget")
			}
		}
		head := first.headAt(first.bucket(key))
		if mode == "bucket" {
			if head != nil || compactRetained.Load() != fake {
				t.Fatal("bucket failure charged/allocated")
			}
		} else {
			if head == nil || *head != 0 || compactRetained.Load() != fake+bucketBytes {
				t.Fatal("bucket-success entry-failure did not retain exact charge/empty index")
			}
		}
		if err := second.admit(compactKey(23, 32), testTime); err != ErrCapacity {
			t.Fatal("other identity bypassed shared budget", err)
		}
		if second.count != 0 || second.head != 0 || second.tail != 0 {
			t.Fatal("second failed admission committed")
		}
		runtime.GC()
		runtime.Gosched()
		if compactRetained.Load() != compactBudget {
			t.Fatal("reachable page prematurely released")
		}
		releaseCompact(fake)
		if err := first.admit(key, testTime); err != nil {
			t.Fatal("failed salt poisoned replay state", err)
		}
		if err := first.admit(key, testTime); err != ErrReplay {
			t.Fatal("successful insertion not protected", err)
		}
		if first.count != 1 || first.head != 0 || first.tail != 1 || *first.headAt(first.bucket(key)) != 1 {
			t.Fatal("recovery index/queue state")
		}
		if err := second.admit(compactKey(23, 32), testTime); err != nil {
			t.Fatal("second identity recovery", err)
		}
		if got := compactRetained.Load(); got != 2*(bucketBytes+entryBytes) {
			t.Fatal("wrong combined charge", got)
		}
		first.expire(testTime.Add(replayTTL))
		second.expire(testTime.Add(replayTTL))
		runtime.GC()
		runtime.Gosched()
		if compactRetained.Load() != 2*(bucketBytes+entryBytes) {
			t.Fatal("expiry uncharged still-reachable reusable pages")
		}
		runtime.KeepAlive(first)
		runtime.KeepAlive(second)
		first = nil
		second = nil
		waitCompactCharge(t, 0)
		t.Log("nonzero capacity failure/recovery, exact indexes and multi-identity accounting verified")
	case "contend":
		fake := compactBudget - 2*bucketBytes - entryBytes
		if !reserveCompact(fake) {
			t.Fatal("reservation")
		}
		owners := [2]*compactSaltStore{new(compactSaltStore), new(compactSaltStore)}
		for _, c := range owners {
			c.init(8)
		}
		var wg sync.WaitGroup
		var got [2]error
		start := make(chan struct{})
		for i := range owners {
			wg.Add(1)
			go func(i int) { defer wg.Done(); <-start; got[i] = owners[i].admit(compactKey(uint64(i+1), 16), testTime) }(i)
		}
		close(start)
		wg.Wait()
		wins := 0
		for i, e := range got {
			if e == nil {
				wins++
				if owners[i].count != 1 {
					t.Fatal("winner not committed")
				}
			} else if e != ErrCapacity || owners[i].count != 0 || owners[i].tail != 0 {
				t.Fatal("loser changed state", e)
			}
		}
		if wins != 1 || compactRetained.Load() != compactBudget {
			t.Fatal("identities exceeded shared entry-page allowance", wins, compactRetained.Load())
		}
		releaseCompact(fake)
		for i, e := range got {
			if e == ErrCapacity {
				if err := owners[i].admit(compactKey(uint64(i+1), 16), testTime); err != nil {
					t.Fatal("loser could not recover", err)
				}
			}
		}
		if compactRetained.Load() != 2*(bucketBytes+entryBytes) {
			t.Fatal("recovered accounting")
		}
		runtime.KeepAlive(owners)
		owners = [2]*compactSaltStore{}
		waitCompactCharge(t, 0)
		t.Log("concurrent independent stores share the same last entry-page quota; loser recovers")
	case "cleanup":
		holder := new(compactSaltStore)
		holder.init(8)
		if err := holder.admit(compactKey(9, 16), testTime); err != nil {
			t.Fatal(err)
		}
		charge := bucketBytes + entryBytes
		if compactRetained.Load() != charge {
			t.Fatal("initial charge")
		}
		fake := compactBudget - charge
		if !reserveCompact(fake) {
			t.Fatal("reserve remainder")
		}
		blocked := new(compactSaltStore)
		blocked.init(8)
		if err := blocked.admit(compactKey(10, 16), testTime); err != ErrCapacity {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			runtime.GC()
			runtime.Gosched()
		}
		if compactRetained.Load() != compactBudget {
			t.Fatal("cleanup ran while owner reachable")
		}
		if err := holder.admit(compactKey(9, 16), testTime); err != ErrReplay {
			t.Fatal("live owner altered")
		}
		runtime.KeepAlive(holder)
		holder = nil
		// Accounting must be returned by actual AddCleanup, never manually for pages.
		waitCompactCharge(t, fake)
		if err := blocked.admit(compactKey(10, 16), testTime); err != nil {
			t.Fatal("cleanup did not restore shared capacity", err)
		}
		if compactRetained.Load() != compactBudget {
			t.Fatal("reallocated budget incorrect")
		}
		releaseCompact(fake)
		runtime.KeepAlive(blocked)
		blocked = nil
		waitCompactCharge(t, 0)
		t.Log("reachable pages keep quota; unreachable cleanup restores quota to another identity")
	default:
		t.Fatal(mode)
	}
}
func waitCompactCharge(t *testing.T, want int64) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		runtime.GC()
		runtime.Gosched()
		if compactRetained.Load() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("cleanup accounting got=%d want=%d", compactRetained.Load(), want)
}
