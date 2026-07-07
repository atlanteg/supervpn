// Package fragment splits oversized L2 frames into wire-safe pieces and
// reassembles them on the receive side.
//
// It exists because the UDP transport wraps each inner Ethernet frame in
// proto+crypto overhead; a full-size frame (~1514 B) then exceeds the path MTU
// and IP-fragments, and fragmented UDP is routinely dropped by DPI (ТСПУ) and
// NAT. Frames that fit one datagram are never touched — only genuinely oversized
// frames (large non-TCP traffic that TCP MSS clamping can't shrink) are split
// into FrameDataFrag pieces, each of which rides its own datagram and is
// reassembled here before delivery.
package fragment

import (
	"sync"
	"time"
)

// Split breaks frame into consecutive pieces of at most maxPiece bytes.
// A frame that already fits is returned as a single piece. maxPiece must be > 0.
func Split(frame []byte, maxPiece int) [][]byte {
	if maxPiece <= 0 || len(frame) <= maxPiece {
		return [][]byte{frame}
	}
	n := (len(frame) + maxPiece - 1) / maxPiece
	pieces := make([][]byte, 0, n)
	for off := 0; off < len(frame); off += maxPiece {
		end := off + maxPiece
		if end > len(frame) {
			end = len(frame)
		}
		pieces = append(pieces, frame[off:end])
	}
	return pieces
}

// NeedsSplit reports whether frame must be fragmented for the given piece size.
func NeedsSplit(frame []byte, maxPiece int) bool {
	return maxPiece > 0 && len(frame) > maxPiece
}

const (
	// reassemblyTTL bounds how long an incomplete frame's pieces are held.
	reassemblyTTL = 2 * time.Second
	// maxPending caps concurrent in-flight partial frames (memory bound); the
	// oldest is dropped on overflow. Oversized frames are rare, so this is small.
	maxPending = 256
)

type partial struct {
	pieces  [][]byte
	count   uint8
	got     int
	total   int       // bytes accumulated so far
	created time.Time
	done    bool // frame already reassembled+returned; kept as a tombstone until TTL
}

// Reassembler collects FrameDataFrag pieces keyed by fragID and returns the
// original frame once every piece has arrived. It is safe for concurrent use.
//
// Duplicate pieces (the same fragID+idx arriving twice, e.g. over the dual UDP
// path when the crypto replay window did not already drop them) are ignored.
// Incomplete frames are evicted after reassemblyTTL or when maxPending is hit.
type Reassembler struct {
	mu      sync.Mutex
	pending map[uint32]*partial
	now     func() time.Time // injectable clock for tests
}

// NewReassembler returns an empty Reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{pending: make(map[uint32]*partial), now: time.Now}
}

// Add records one piece. It returns the fully reassembled frame when this piece
// completes the set, or nil if more pieces are still needed (or the piece was a
// duplicate / invalid). piece is copied, so the caller may reuse its buffer.
func (r *Reassembler) Add(fragID uint32, idx, count uint8, piece []byte) []byte {
	if count == 0 || idx >= count {
		return nil
	}
	// Single-piece "fragment" — degenerate but valid; deliver immediately.
	if count == 1 {
		out := make([]byte, len(piece))
		copy(out, piece)
		return out
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	p, ok := r.pending[fragID]
	if ok && p.done {
		// Frame already delivered; this is a late duplicate piece from the other
		// UDP path (the client's two recvLoops have independent replay windows, so
		// crypto does not drop it here). Ignore it — do NOT re-complete and inject
		// the frame twice. The tombstone is reclaimed by evictLocked after the TTL.
		return nil
	}
	if !ok {
		r.evictLocked(now)
		p = &partial{pieces: make([][]byte, count), count: count, created: now}
		r.pending[fragID] = p
	} else if p.count != count {
		// fragID reuse with a different piece count — discard the stale partial.
		p = &partial{pieces: make([][]byte, count), count: count, created: now}
		r.pending[fragID] = p
	}

	if p.pieces[idx] != nil {
		return nil // duplicate piece
	}
	cp := make([]byte, len(piece))
	copy(cp, piece)
	p.pieces[idx] = cp
	p.got++
	p.total += len(cp)

	if p.got < int(p.count) {
		return nil
	}

	// Complete: concatenate in index order.
	out := make([]byte, 0, p.total)
	for _, pc := range p.pieces {
		out = append(out, pc...)
	}
	// Keep a tombstone (pieces freed) so duplicate pieces from the slower path are
	// dropped instead of re-creating the entry and re-delivering the frame.
	p.done = true
	p.pieces = nil
	return out
}

// evictLocked drops expired partials, and if the map is still at capacity, the
// oldest one. Caller must hold r.mu.
func (r *Reassembler) evictLocked(now time.Time) {
	for id, p := range r.pending {
		if now.Sub(p.created) > reassemblyTTL {
			delete(r.pending, id)
		}
	}
	if len(r.pending) < maxPending {
		return
	}
	var oldestID uint32
	var oldest time.Time
	first := true
	for id, p := range r.pending {
		if first || p.created.Before(oldest) {
			oldestID, oldest, first = id, p.created, false
		}
	}
	if !first {
		delete(r.pending, oldestID)
	}
}
