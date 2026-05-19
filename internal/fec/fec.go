// Package fec implements Forward Error Correction for supervpn UDP transport.
//
// Algorithm: systematic Reed-Solomon over GF(2^8) in a "pro-video" style matrix.
// Packets are grouped into blocks of K data packets; R repair packets are appended.
// Any K packets from the K+R set are sufficient to reconstruct all K originals.
//
// Default: K=20 data, R=1 repair → ~5% overhead, recovers from any single loss.
// Configurable at runtime for higher redundancy.
package fec

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	DefaultK     = 20  // data packets per block
	DefaultR     = 6   // repair packets per block — handles burst of 6, ≈30% overhead, ~99.9% recovery at 5% loss
	MaxK         = 128
	MaxR         = 32
	maxOldBlocks = 8              // minimum block-ID distance before a block is eligible for expiry
	blockKeepAge = 2 * time.Second // blocks with recent activity are kept for this long regardless of block distance
)

var ErrUnrecoverable = errors.New("fec: too many losses in block, unrecoverable")

// Encoder groups outgoing data packets into blocks and generates repair symbols.
// For R=1 it uses fast XOR. For R>1 it uses Reed-Solomon over GF(2^8).
type Encoder struct {
	k, r    int
	buf     [][]byte
	blockID uint32
	enc     reedsolomon.Encoder // nil when r==1
}

func NewEncoder(k, r int) (*Encoder, error) {
	if k < 1 || k > MaxK {
		return nil, fmt.Errorf("fec: k=%d out of range [1,%d]", k, MaxK)
	}
	if r < 0 || r > MaxR {
		return nil, fmt.Errorf("fec: r=%d out of range [0,%d]", r, MaxR)
	}
	e := &Encoder{k: k, r: r, buf: make([][]byte, 0, k)}
	if r > 1 {
		var err error
		e.enc, err = reedsolomon.New(k, r)
		if err != nil {
			return nil, fmt.Errorf("fec: rs init: %w", err)
		}
	}
	return e, nil
}

// Add accepts one data packet. Returns repair symbols when a block is full (every K calls).
// Returns nil otherwise. The caller must send data + repairs in order.
func (e *Encoder) Add(pkt []byte) [][]byte {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	e.buf = append(e.buf, cp)
	if len(e.buf) < e.k {
		return nil
	}
	var repairs [][]byte
	if e.r == 0 {
		repairs = nil
	} else if e.r == 1 {
		repairs = [][]byte{xorAll(e.buf)}
	} else {
		repairs = rsEncode(e.enc, e.buf, e.k, e.r)
	}
	e.buf = e.buf[:0]
	e.blockID++
	return repairs
}

// BlockID returns the current block ID (incremented after each full block).
func (e *Encoder) BlockID() uint32 { return e.blockID }

// Decoder reassembles FEC blocks, recovering lost packets when possible.
type Decoder struct {
	k, r    int
	mu      sync.Mutex
	blocks  map[uint32]*decBlock
	maxSeen uint32
	enc     reedsolomon.Encoder // nil when r==1
}

type decBlock struct {
	data         [][]byte  // k slots; nil = not received
	repair       [][]byte  // r slots; nil = not received
	present      []bool    // k+r flags
	count        int       // received count
	delivered    int       // consecutive data packets already returned to caller
	done         bool
	lastActivity time.Time // updated on every packet arrival
}

func NewDecoder(k, r int) (*Decoder, error) {
	d := &Decoder{k: k, r: r, blocks: make(map[uint32]*decBlock)}
	if r > 1 {
		var err error
		d.enc, err = reedsolomon.New(k, r)
		if err != nil {
			return nil, fmt.Errorf("fec: rs decoder init: %w", err)
		}
	}
	return d, nil
}

// AddData records a received data packet. idx is the packet's index within its block [0,K).
// Returns the complete block (k data packets) when recovery is possible, nil otherwise.
func (d *Decoder) AddData(blockID uint32, idx int, pkt []byte) ([][]byte, error) {
	return d.add(blockID, idx, pkt, false)
}

// AddRepair records a received FEC repair symbol. idx is the repair index [0,R).
func (d *Decoder) AddRepair(blockID uint32, idx int, pkt []byte) ([][]byte, error) {
	return d.add(blockID, idx, pkt, true)
}

func (d *Decoder) add(blockID uint32, idx int, pkt []byte, isRepair bool) ([][]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// track max seen block for expiry
	if blockID > d.maxSeen {
		d.maxSeen = blockID
		d.expire()
	}

	b := d.getOrCreate(blockID)
	if b.done {
		return nil, nil
	}

	cp := make([]byte, len(pkt))
	copy(cp, pkt)

	if isRepair {
		if idx < 0 || idx >= d.r || b.present[d.k+idx] {
			return nil, nil
		}
		b.repair[idx] = cp
		b.present[d.k+idx] = true
	} else {
		if idx < 0 || idx >= d.k || b.present[idx] {
			return nil, nil
		}
		b.data[idx] = cp
		b.present[idx] = true
	}
	b.count++
	b.lastActivity = time.Now()

	return d.tryRecover(blockID, b)
}

func (d *Decoder) getOrCreate(id uint32) *decBlock {
	if b, ok := d.blocks[id]; ok {
		return b
	}
	b := &decBlock{
		data:    make([][]byte, d.k),
		repair:  make([][]byte, d.r),
		present: make([]bool, d.k+d.r),
	}
	d.blocks[id] = b
	return b
}

func (d *Decoder) expire() {
	if d.maxSeen < uint32(maxOldBlocks) {
		return
	}
	threshold := d.maxSeen - uint32(maxOldBlocks)
	now := time.Now()
	for id, b := range d.blocks {
		if id >= threshold {
			continue // too recent to consider
		}
		// Blocks that never received a packet can be dropped immediately.
		if b.lastActivity.IsZero() {
			delete(d.blocks, id)
			continue
		}
		// Keep recently-active blocks long enough for delayed repair packets to
		// arrive (default repairDelay=50ms); blockKeepAge provides 4× margin.
		if now.Sub(b.lastActivity) > blockKeepAge {
			delete(d.blocks, id)
		}
	}
}

// FlushStale delivers packets that are stuck behind an unrecoverable gap in a
// block that has had no activity for longer than maxAge. It skips blocks that
// are simply filling slowly (no packets beyond b.delivered yet) — those must
// not be closed prematurely, or later arriving packets would be lost.
func (d *Decoder) FlushStale(maxAge time.Duration) [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	var out [][]byte
	for _, b := range d.blocks {
		if b.done || b.lastActivity.IsZero() || now.Sub(b.lastActivity) < maxAge {
			continue
		}
		// Only flush if there are packets present beyond the current delivery
		// position — meaning real frames are stuck behind an unrecoverable gap.
		// If nothing is present past b.delivered the block is just filling slowly
		// (low-rate traffic); closing it would drop all subsequent packets.
		stuck := false
		for i := b.delivered; i < d.k; i++ {
			if b.present[i] {
				stuck = true
				break
			}
		}
		if !stuck {
			continue
		}
		for i := b.delivered; i < d.k; i++ {
			if b.present[i] {
				out = append(out, b.data[i])
			}
		}
		b.delivered = d.k
		b.done = true
		// Don't delete — leave for expire() so late-arriving packets are dropped.
	}
	return out
}

func (d *Decoder) tryRecover(_ uint32, b *decBlock) ([][]byte, error) {
	// If there are gaps, try FEC recovery before delivering.
	missing := 0
	for i := b.delivered; i < d.k; i++ {
		if !b.present[i] {
			missing++
		}
	}
	if missing > 0 {
		repairs := 0
		for i := 0; i < d.r; i++ {
			if b.present[d.k+i] {
				repairs++
			}
		}
		if missing <= repairs {
			var result [][]byte
			var err error
			if d.r == 1 {
				result, err = xorRecover(b.data, b.repair[0], d.k)
			} else {
				result, err = rsRecover(d.enc, b.data, b.repair, d.k, d.r)
			}
			if err != nil {
				return nil, err
			}
			for i, pkt := range result {
				if !b.present[i] {
					b.data[i] = pkt
					b.present[i] = true
				}
			}
		}
	}

	// Deliver all consecutive in-order packets starting from b.delivered.
	var out [][]byte
	for b.delivered < d.k && b.present[b.delivered] {
		out = append(out, b.data[b.delivered])
		b.delivered++
	}
	if b.delivered == d.k {
		b.done = true
		// Keep the block in the map so arriving repair packets for this blockID
		// hit the b.done check and are silently dropped instead of triggering
		// re-delivery. expire() will remove it once maxSeen advances past it.
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// xorAll computes XOR of all packets, padding shorter ones with zeros.
func xorAll(pkts [][]byte) []byte {
	maxLen := 0
	for _, p := range pkts {
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}
	out := make([]byte, maxLen)
	for _, p := range pkts {
		for i, b := range p {
			out[i] ^= b
		}
	}
	return out
}

// xorRecover recovers the single missing data packet via XOR.
func xorRecover(data [][]byte, repair []byte, k int) ([][]byte, error) {
	// Find the missing index
	missingIdx := -1
	for i, p := range data {
		if p == nil {
			if missingIdx >= 0 {
				return nil, ErrUnrecoverable // more than 1 missing
			}
			missingIdx = i
		}
	}
	if missingIdx < 0 {
		return data, nil // nothing missing
	}
	// recovered = repair XOR all_present_data
	recovered := make([]byte, len(repair))
	copy(recovered, repair)
	for i, p := range data {
		if i == missingIdx {
			continue
		}
		for j, b := range p {
			if j < len(recovered) {
				recovered[j] ^= b
			}
		}
	}
	data[missingIdx] = recovered
	return data, nil
}

// rsEncode generates R repair symbols for K data shards using Reed-Solomon.
func rsEncode(enc reedsolomon.Encoder, data [][]byte, k, r int) [][]byte {
	// RS requires all shards to be the same length; pad to max
	maxLen := 0
	for _, p := range data {
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}
	shards := make([][]byte, k+r)
	for i, p := range data {
		shard := make([]byte, maxLen)
		copy(shard, p)
		shards[i] = shard
	}
	for i := k; i < k+r; i++ {
		shards[i] = make([]byte, maxLen)
	}
	if err := enc.Encode(shards); err != nil {
		return nil
	}
	return shards[k:]
}

// rsRecover reconstructs missing data shards using Reed-Solomon.
func rsRecover(enc reedsolomon.Encoder, data, repair [][]byte, k, r int) ([][]byte, error) {
	maxLen := 0
	for _, p := range data {
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}
	for _, p := range repair {
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}
	shards := make([][]byte, k+r)
	for i, p := range data {
		if p != nil {
			shard := make([]byte, maxLen)
			copy(shard, p)
			shards[i] = shard
		}
	}
	for i, p := range repair {
		if p != nil {
			shard := make([]byte, maxLen)
			copy(shard, p)
			shards[k+i] = shard
		}
	}
	if err := enc.ReconstructData(shards); err != nil {
		return nil, ErrUnrecoverable
	}
	return shards[:k], nil
}
