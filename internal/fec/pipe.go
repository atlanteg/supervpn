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

// repairJob carries a completed FEC block's repair symbols to the background sender.
type repairJob struct {
	sendAt  time.Time
	blockID uint32
	repairs [][]byte
}

// Pipe integrates FEC encoding (send path) and decoding (receive path) for one session.
// Send is safe for concurrent callers: p.mu serialises access to the encoder so
// each frame is assigned a canonical (blockID, pktIdx) atomically, and the send
// callbacks are themselves concurrency-safe. (The server hub legitimately calls a
// destination session's Send from multiple source-session goroutines.) The receive
// side is likewise safe from multiple recvLoops — the decoder has its own mutex.
type Pipe struct {
	enc         *Encoder
	dec         *Decoder
	sendData    SendDataFn
	sendRepair  SendRepairFn
	repairDelay time.Duration // if >0, repair packets are sent after this delay
	mu          sync.Mutex   // protects enc (send path)
	pktIdx      uint16       // index of next packet within current block
	// repairCh is non-nil when repairDelay > 0. A single background goroutine
	// (started by StartRepairSender) drains it, sleeping until each job's sendAt.
	// This replaces the previous goroutine-per-block-completion approach.
	repairCh chan repairJob
}

// NewPipe creates a FEC pipe with the given K/R parameters and send callbacks.
// repairDelay > 0 causes repair packets to be sent asynchronously after the delay,
// providing temporal separation from data packets so burst losses don't kill both.
// sendData is called for every outgoing data packet (must not be nil).
// sendRepair is called for every repair symbol (may be nil when r==0).
func NewPipe(k, r int, repairDelay time.Duration, sendData SendDataFn, sendRepair SendRepairFn) (*Pipe, error) {
	enc, err := NewEncoder(k, r)
	if err != nil {
		return nil, err
	}
	dec, err := NewDecoder(k, r)
	if err != nil {
		return nil, err
	}
	p := &Pipe{
		enc:         enc,
		dec:         dec,
		sendData:    sendData,
		sendRepair:  sendRepair,
		repairDelay: repairDelay,
	}
	if repairDelay > 0 && sendRepair != nil {
		// Buffer sized for ~0.5 s worth of blocks at K=1/2500 pps; drops to immediate
		// send on overflow rather than blocking the hot path.
		p.repairCh = make(chan repairJob, 2048)
	}
	return p, nil
}

// Send passes a plaintext L2 frame through the FEC encoder and onto the wire.
// It calls sendData once per frame, and sendRepair R times when a block completes
// (after repairDelay if configured).
// Thread-safety: do not call Send concurrently.
func (p *Pipe) Send(frame []byte) error {
	p.mu.Lock()
	currentBlockID := p.enc.BlockID()
	currentPktIdx := p.pktIdx
	repairs := p.enc.Add(frame)
	p.pktIdx++
	completedBlockID := currentBlockID
	if repairs != nil {
		p.pktIdx = 0
	}
	p.mu.Unlock()

	if err := p.sendData(currentBlockID, currentPktIdx, frame); err != nil {
		return err
	}
	if len(repairs) == 0 || p.sendRepair == nil {
		return nil
	}
	if p.repairDelay > 0 {
		// Hand off to the single background sender goroutine (started by
		// StartRepairSender). If the channel is full — extremely unlikely at
		// normal rates — fall back to immediate send so repairs aren't lost.
		job := repairJob{
			sendAt:  time.Now().Add(p.repairDelay),
			blockID: completedBlockID,
			repairs: repairs,
		}
		select {
		case p.repairCh <- job:
		default:
			for i, rep := range repairs {
				_ = p.sendRepair(completedBlockID, uint8(i), rep)
			}
		}
	} else {
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

// RepairBlockDone reports whether blockID has already been fully delivered.
// Callers can use this to skip decryption of repair packets for completed blocks.
func (p *Pipe) RepairBlockDone(blockID uint32) bool {
	return p.dec.BlockDone(blockID)
}

// StartRepairSender starts the single background goroutine that delivers delayed
// repair packets. Must be called once after NewPipe when repairDelay > 0.
// The goroutine stops when ctx is cancelled. Calling StartRepairSender when
// repairDelay == 0 (repairCh == nil) is a no-op.
func (p *Pipe) StartRepairSender(ctx context.Context) {
	if p.repairCh == nil {
		return
	}
	go func() {
		// Single timer reused across all repair jobs to avoid per-job allocations.
		timer := time.NewTimer(0)
		if !timer.Stop() {
			<-timer.C
		}
		for {
			select {
			case <-ctx.Done():
				return
			case job, ok := <-p.repairCh:
				if !ok {
					return
				}
				// Sleep until the scheduled send time, but wake early on ctx cancel.
				if d := time.Until(job.sendAt); d > 0 {
					timer.Reset(d)
					select {
					case <-timer.C:
					case <-ctx.Done():
						if !timer.Stop() {
							<-timer.C
						}
						return
					}
				}
				for i, rep := range job.repairs {
					_ = p.sendRepair(job.blockID, uint8(i), rep)
				}
			}
		}
	}()
}

// StartFlush runs a background goroutine that calls FlushStale every maxAge/4.
// For each flushed frame it calls deliver. Stops when ctx is cancelled.
// Intended to bound delivery latency when a mid-block loss burst is unrecoverable.
//
// orderMu (the caller's per-session delivery lock) is held across the whole
// batch — the FlushStale collection AND every deliver — so the flush is atomic
// with the receive path's decode→forward. Without it, a recv worker forwarding a
// newer block could interleave between collecting and delivering the stale
// frames, re-introducing the exact reordering orderMu exists to prevent. The
// deliver callback must therefore NOT take orderMu itself. Pass nil to disable
// locking (single-threaded callers/tests).
func (p *Pipe) StartFlush(ctx context.Context, maxAge time.Duration, orderMu *sync.Mutex, deliver func([]byte)) {
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
				if orderMu != nil {
					orderMu.Lock()
				}
				for _, frame := range p.dec.FlushStale(maxAge) {
					deliver(frame)
				}
				if orderMu != nil {
					orderMu.Unlock()
				}
			}
		}
	}()
}
