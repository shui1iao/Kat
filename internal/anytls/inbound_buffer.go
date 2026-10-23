package anytls

import "sync"

// Exact-capacity cache: a 16B frame can never borrow a 64KiB allocation while
// being charged for 16B. Sessions reserve len(payload)+7 BEFORE this allocation
// is borrowed; queued, partial-read and in-flight frames remain fully charged.
const inboundCacheFrames = 16
const inboundCacheBytes = 512 * 1024

var inboundBuffers struct {
	sync.Mutex
	frames [][]byte
	bytes  int
}

func takeInboundFrame(n int) []byte {
	inboundBuffers.Lock()
	for i, p := range inboundBuffers.frames {
		if cap(p) == n {
			last := len(inboundBuffers.frames) - 1
			inboundBuffers.frames[i] = inboundBuffers.frames[last]
			inboundBuffers.frames[last] = nil
			inboundBuffers.frames = inboundBuffers.frames[:last]
			inboundBuffers.bytes -= n
			inboundBuffers.Unlock()
			return p[:n]
		}
	}
	inboundBuffers.Unlock()
	return make([]byte, n)
}
func releaseInboundFrame(p []byte) {
	if p == nil {
		return
	}
	p = p[:cap(p)]
	clear(p)
	inboundBuffers.Lock()
	defer inboundBuffers.Unlock()
	if len(p) > inboundCacheBytes {
		return
	}
	for len(inboundBuffers.frames) > 0 && (len(inboundBuffers.frames) >= inboundCacheFrames || inboundBuffers.bytes+len(p) > inboundCacheBytes) {
		old := inboundBuffers.frames[0]
		inboundBuffers.bytes -= cap(old)
		copy(inboundBuffers.frames, inboundBuffers.frames[1:])
		last := len(inboundBuffers.frames) - 1
		inboundBuffers.frames[last] = nil
		inboundBuffers.frames = inboundBuffers.frames[:last]
	}
	if len(inboundBuffers.frames) < inboundCacheFrames && inboundBuffers.bytes+len(p) <= inboundCacheBytes {
		inboundBuffers.frames = append(inboundBuffers.frames, p)
		inboundBuffers.bytes += len(p)
	}
}
