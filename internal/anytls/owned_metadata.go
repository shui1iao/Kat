package anytls

import "sync/atomic"

// Original full owned-wire process allowance was16*65528B. Right-sizing actual
// wire leases to16*32775B leaves room for7*65535B native receive buffers AND
// this <=16KiB metadata reserve (total999529B <1048448B). Active descriptors
// replace the same old64B frame+completion allocation, never extra payload.
const OwnedMetadataCacheSlots = 16
const OwnedMetadataReservedBytes = 16 * 1024

var ownedMetadataFree = make(chan *outbound, OwnedMetadataCacheSlots)

func takeOwnedMetadata() *outbound {
	var f *outbound
	select {
	case f = <-ownedMetadataFree:
	default:
		f = &outbound{done: make(chan error, 1)}
	}
	f.reusable = true
	atomic.StoreInt32(&f.refs, 2)
	return f
}
func releaseOwnedMetadata(f *outbound) {
	if !f.reusable {
		return
	}
	if atomic.AddInt32(&f.refs, -1) != 0 {
		return
	}
	// Both sender and actual transport writer are gone. On timeout the writer
	// can be the last owner; discard any unobserved buffered completion error.
	select {
	case <-f.done:
	default:
	}
	f.wire = nil
	f.stream = nil
	f.release = nil
	f.cost = 0
	f.command = 0
	f.sendWatchdog = false
	select {
	case ownedMetadataFree <- f:
	default:
	}
}
