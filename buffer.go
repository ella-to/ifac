package ifac

import "sync"

// largeBufSize fits the largest packet plus the 4-byte utun header macOS
// adds in both directions.
const largeBufSize = MaxFrameSize + 4

// bufClasses are the pooled buffer sizes, smallest first. Queued frames hold
// a buffer sized to the packet rather than to MaxFrameSize: the first class
// covers the usual 1500-byte MTU, the second jumbo frames. A full inbox of
// MTU-sized packets therefore pins about 2 MB rather than 64 MB, and a pool
// refilled after GC allocates 2 KB per buffer rather than 64 KB.
var bufClasses = [...]int{2048, 16384, largeBufSize}

var bufPools [len(bufClasses)]sync.Pool

func init() {
	for i, size := range bufClasses {
		bufPools[i].New = func() any {
			b := make([]byte, size)
			return &b
		}
	}
}

// getBuffer returns a pooled buffer of at least n bytes (n <= largeBufSize).
// Its length is the full class size.
func getBuffer(n int) *[]byte {
	for i, size := range bufClasses {
		if n <= size {
			return bufPools[i].Get().(*[]byte)
		}
	}
	panic("ifac: buffer request exceeds largeBufSize")
}

// putBuffer returns a buffer obtained from getBuffer to its pool.
func putBuffer(bp *[]byte) {
	for i, size := range bufClasses {
		if cap(*bp) == size {
			*bp = (*bp)[:size]
			bufPools[i].Put(bp)
			return
		}
	}
}
