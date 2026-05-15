// Package fec — pipe.go
package fec

import (
	"context"
	"sync"
	"time"
)

// SendDataFn is called for each outgoing data packet.
// blockID and pktIdx identify the packet's position in its FEC block.
type SendDataFn func(blockID uint32, pktIdx uint16, data []byte) error

// SendRepairFn is called for each repair symbol generated when a block is full.
type SendRepairFn func(blockID uint32, repairIdx uint8, data []byte) error

// Pipe integrates FEC encoding (send path) and decoding (receive path) for one session.
// It is safe for concurrent use from a single sender goroutine + single receiver goroutine.
// Do NOT call Send from multiple goroutines simultaneously — use external locking if needed.
type Pipe struct {
	enc        *Encoder
	dec        *Decoder
	sendData   SendDataFn
	sendRepair SendRepairFn
	mu         sync.Mutex // protects enc (send path)
	pktIdx     uint16     // index of next packet within current block
}

// NewPipe creates a FEC pipe with the given K/R parameters and send callbacks.
// sendData is called for every outgoing data packet (must not be nil).
// sendRepair is called for every repair symbol (may be nil when r==0).
func NewPipe(k, r int, sendData SendDataFn, sendRepair SendRepairFn) (*Pipe, error) {
	enc, err := NewEncoder(k, r)
	if err != nil {
		return nil, err
	}
	dec, err := NewDecoder(k, r)
	if err != nil {
		return nil, err
	}
	return &Pipe{
		enc:        enc,
		dec:        dec,
		sendData:   sendData,
		sendRepair: sendRepair,
	}, nil
}

// Send passes a plaintext L2 frame through the FEC encoder and onto the wire.
// It calls sendData once per frame, and sendRepair R times when a block completes.
// Thread-safety: do not call Send concurrently.
func (p *Pipe) Send(frame []byte) error {
	p.mu.Lock()
	currentBlockID := p.enc.BlockID() // block this packet belongs to
	currentPktIdx := p.pktIdx
	repairs := p.enc.Add(frame)
	p.pktIdx++
	completedBlockID := currentBlockID // save before potential increment
	if repairs != nil {
		p.pktIdx = 0
	}
	p.mu.Unlock()

	if err := p.sendData(currentBlockID, currentPktIdx, frame); err != nil {
		return err
	}
	if len(repairs) > 0 && p.sendRepair != nil {
		for i, rep := range repairs {
			if err := p.sendRepair(completedBlockID, uint8(i), rep); err != nil {
				return err
			}
		}
	}
	return nil
}

// RecvData feeds a received data packet into the FEC decoder.
// Returns the complete block of K frames when recovery is possible, nil otherwise.
// Safe to call from one goroutine while Send is called from another.
func (p *Pipe) RecvData(blockID uint32, pktIdx uint16, data []byte) ([][]byte, error) {
	return p.dec.AddData(blockID, int(pktIdx), data)
}

// RecvRepair feeds a received repair symbol into the FEC decoder.
// Returns the complete block of K frames when recovery is possible, nil otherwise.
func (p *Pipe) RecvRepair(blockID uint32, repairIdx, blockK, blockR uint8, data []byte) ([][]byte, error) {
	return p.dec.AddRepair(blockID, int(repairIdx), data)
}

// StartFlush runs a background goroutine that calls FlushStale every maxAge/4.
// For each flushed frame it calls deliver. Stops when ctx is cancelled.
// Intended to bound delivery latency when a mid-block loss burst is unrecoverable.
func (p *Pipe) StartFlush(ctx context.Context, maxAge time.Duration, deliver func([]byte)) {
	tick := maxAge / 4
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, frame := range p.dec.FlushStale(maxAge) {
					deliver(frame)
				}
			}
		}
	}()
}
