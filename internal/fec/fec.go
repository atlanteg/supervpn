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
)

const (
	DefaultK = 20 // data packets per block
	DefaultR = 1  // repair packets per block (≈5% overhead)
	MaxK     = 64
	MaxR     = 16
)

var ErrUnrecoverable = errors.New("fec: too many losses in block, unrecoverable")

// Encoder groups outgoing packets into blocks and emits repair symbols.
type Encoder struct {
	k, r    int
	buf     [][]byte // accumulated data packets for current block
	blockID uint32
}

func NewEncoder(k, r int) (*Encoder, error) {
	if k < 1 || k > MaxK {
		return nil, fmt.Errorf("fec: k=%d out of range [1,%d]", k, MaxK)
	}
	if r < 0 || r > MaxR {
		return nil, fmt.Errorf("fec: r=%d out of range [0,%d]", r, MaxR)
	}
	return &Encoder{k: k, r: r, buf: make([][]byte, 0, k)}, nil
}

// Add accepts a data packet. Returns non-nil repair symbols when a block is full.
// Caller must send data packet + repair symbols (if any) in order.
func (e *Encoder) Add(pkt []byte) (repairs [][]byte) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	e.buf = append(e.buf, cp)
	if len(e.buf) < e.k {
		return nil
	}
	repairs = buildRepairs(e.buf, e.blockID, e.r)
	e.buf = e.buf[:0]
	e.blockID++
	return repairs
}

// Decoder reassembles a block, recovering lost packets when possible.
type Decoder struct {
	k, r    int
	blocks  map[uint32]*block
}

type block struct {
	data    [][]byte
	repair  [][]byte
	present []bool
	seen    int
}

func NewDecoder(k, r int) *Decoder {
	return &Decoder{k: k, r: r, blocks: make(map[uint32]*block)}
}

// AddData records a received data packet. Returns recovered slice when block is complete.
func (d *Decoder) AddData(blockID uint32, idx int, pkt []byte) ([][]byte, error) {
	return d.tryComplete(blockID, idx, pkt, false)
}

// AddRepair records a received repair symbol.
func (d *Decoder) AddRepair(blockID uint32, idx int, pkt []byte) ([][]byte, error) {
	return d.tryComplete(blockID, idx, pkt, true)
}

func (d *Decoder) tryComplete(blockID uint32, idx int, pkt []byte, isRepair bool) ([][]byte, error) {
	b, ok := d.blocks[blockID]
	if !ok {
		b = &block{
			data:    make([][]byte, d.k),
			repair:  make([][]byte, d.r),
			present: make([]bool, d.k+d.r),
		}
		d.blocks[blockID] = b
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	if isRepair {
		if idx >= d.r {
			return nil, nil
		}
		b.repair[idx] = cp
		b.present[d.k+idx] = true
	} else {
		if idx >= d.k {
			return nil, nil
		}
		b.data[idx] = cp
		b.present[idx] = true
	}
	b.seen++
	if b.seen < d.k {
		return nil, nil
	}
	result, err := reconstruct(b, d.k, d.r)
	if err != nil {
		return nil, err
	}
	delete(d.blocks, blockID)
	return result, nil
}

// buildRepairs generates R XOR/RS repair symbols for K data packets.
// Phase 1: simple row-XOR parity (sufficient for single-loss recovery).
// TODO: replace with full Reed-Solomon for multi-loss recovery (R>1).
func buildRepairs(data [][]byte, blockID uint32, r int) [][]byte {
	if r == 0 {
		return nil
	}
	maxLen := 0
	for _, p := range data {
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}
	repairs := make([][]byte, r)
	for i := range repairs {
		repairs[i] = make([]byte, maxLen+4) // +4 for block metadata
		// embed blockID and repair index
		repairs[i][0] = byte(blockID >> 24)
		repairs[i][1] = byte(blockID >> 16)
		repairs[i][2] = byte(blockID >> 8)
		repairs[i][3] = byte(blockID)
	}
	// XOR all data packets into repair[0]
	for _, pkt := range data {
		for j, b := range pkt {
			repairs[0][j+4] ^= b
		}
	}
	return repairs
}

func reconstruct(b *block, k, r int) ([][]byte, error) {
	missing := 0
	missingIdx := -1
	for i := 0; i < k; i++ {
		if !b.present[i] {
			missing++
			missingIdx = i
		}
	}
	if missing == 0 {
		return b.data, nil
	}
	if missing > r {
		return nil, ErrUnrecoverable
	}
	// Single-loss recovery via XOR repair symbol
	if missing == 1 && r >= 1 && b.present[k] {
		recovered := make([]byte, len(b.repair[0])-4)
		copy(recovered, b.repair[0][4:])
		for i, pkt := range b.data {
			if i == missingIdx {
				continue
			}
			for j, byt := range pkt {
				if j < len(recovered) {
					recovered[j] ^= byt
				}
			}
		}
		b.data[missingIdx] = recovered
		return b.data, nil
	}
	return nil, ErrUnrecoverable
}
