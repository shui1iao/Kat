//go:build linux

package kernel

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestAnyTLSRawReadNoIdleLeaseAndCancel(t *testing.T) {
	for _, mode := range []string{"deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer := ss2017TCPPair(t)
			defer reader.Close()
			defer writer.Close()
			var last atomic.Int64
			read := newAnyTLSDownRead(&activityStream{reader, &last}, reader)
			if read == nil {
				t.Fatal("raw path unavailable")
			}
			if mode == "deadline" {
				reader.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
			}
			done := make(chan error, 1)
			go func() {
				_, lease, e := read(make([]byte, 16377))
				if lease != nil {
					releaseAnyTLSDown(lease)
				}
				done <- e
			}()
			time.Sleep(15 * time.Millisecond)
			if len(anyTLSDownSlots) != 0 {
				reader.Close()
				<-done
				t.Fatal("idle netpoll owns a charged lease")
			}
			if mode == "close" {
				reader.Close()
			}
			select {
			case e := <-done:
				if e == nil || mode == "deadline" && !errors.Is(e, os.ErrDeadlineExceeded) {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				reader.Close()
				<-done
				t.Fatal("read did not cancel")
			}
			if len(anyTLSDownSlots) != 0 || last.Load() != 0 {
				t.Fatal("empty wait activity/lease leak")
			}
		})
	}
}
func TestAnyTLSRawReadImmediateTailAndFallbackBudget(t *testing.T) {
	for _, noLease := range []bool{false, true} {
		reader, writer := ss2017TCPPair(t)
		reader.SetDeadline(time.Now().Add(time.Second))
		writer.SetDeadline(time.Now().Add(time.Second))
		var held [][]byte
		if noLease {
			for i := 0; i < anyTLSDownLeases; i++ {
				held = append(held, leaseAnyTLSDown())
			}
		}
		payload := []byte("no-batch-wait-tail")
		_, e := writer.Write(payload)
		if e != nil {
			t.Fatal(e)
		}
		writer.CloseWrite()
		var last atomic.Int64
		read := newAnyTLSDownRead(&activityStream{reader, &last}, reader)
		data, lease, e := read(make([]byte, 16377))
		if e != nil || !bytes.Equal(data, payload) || last.Load() == 0 {
			t.Fatal("tail not returned immediately", e)
		}
		if noLease && lease != nil {
			t.Fatal("over budget")
		}
		if !noLease && lease == nil {
			t.Fatal("expected owned wire")
		}
		if lease != nil {
			releaseAnyTLSDown(lease)
			if !bytes.Equal(lease[:cap(lease)], make([]byte, cap(lease))) {
				t.Fatal("not fully cleared")
			}
		}
		_, lease, e = read(make([]byte, 16377))
		if lease != nil {
			releaseAnyTLSDown(lease)
		}
		if e != io.EOF {
			t.Fatal(e)
		}
		for _, b := range held {
			releaseAnyTLSDown(b)
		}
		reader.Close()
		writer.Close()
		if len(anyTLSDownSlots) != 0 {
			t.Fatal("lease leak")
		}
	}
}
