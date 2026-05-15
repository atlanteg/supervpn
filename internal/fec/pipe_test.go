package fec

import (
	"bytes"
	"testing"
)

// makeFrames generates n distinct test frames of varying sizes.
func makeFrames(n int) [][]byte {
	frames := make([][]byte, n)
	for i := range frames {
		sz := 64 + i*3
		f := make([]byte, sz)
		for j := range f {
			f[j] = byte(i*7 + j*3)
		}
		frames[i] = f
	}
	return frames
}

// TestPipe_SendRecv_NoLoss: all K frames delivered immediately (streaming).
func TestPipe_SendRecv_NoLoss(t *testing.T) {
	const K, R = 5, 1

	type dataPkt struct {
		blockID uint32
		pktIdx  uint16
		data    []byte
	}
	var dataPkts []dataPkt

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			dataPkts = append(dataPkts, dataPkt{blockID, pktIdx, cp})
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}

	originals := makeFrames(K)
	for _, f := range originals {
		if err := pipe.Send(f); err != nil {
			t.Fatal(err)
		}
	}

	// Feed all K data packets; each should be delivered immediately.
	var all [][]byte
	for _, dp := range dataPkts {
		result, err := pipe.RecvData(dp.blockID, dp.pktIdx, dp.data)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, result...)
	}

	if len(all) != K {
		t.Fatalf("expected %d frames total, got %d", K, len(all))
	}
	for i, orig := range originals {
		rec := all[i]
		if len(rec) < len(orig) {
			t.Errorf("frame %d too short: got %d bytes, want at least %d", i, len(rec), len(orig))
		} else if !bytes.Equal(rec[:len(orig)], orig) {
			t.Errorf("frame %d prefix mismatch", i)
		}
	}
}

// TestPipe_SendRecv_OneLoss: drop pktIdx=2, recover via XOR repair.
// Frames before the gap (0,1) are delivered streaming; frames after (2,3,4) on repair.
func TestPipe_SendRecv_OneLoss(t *testing.T) {
	const K, R = 5, 1
	const dropIdx = 2

	type dataPkt struct {
		blockID uint32
		pktIdx  uint16
		data    []byte
	}
	type repairPkt struct {
		blockID   uint32
		repairIdx uint8
		data      []byte
	}

	var dataPkts []dataPkt
	var repairPkts []repairPkt

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			dataPkts = append(dataPkts, dataPkt{blockID, pktIdx, cp})
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			repairPkts = append(repairPkts, repairPkt{blockID, repairIdx, cp})
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	originals := makeFrames(K)
	for _, f := range originals {
		if err := pipe.Send(f); err != nil {
			t.Fatal(err)
		}
	}

	// Feed all data except dropped; accumulate delivered.
	var all [][]byte
	for _, dp := range dataPkts {
		if int(dp.pktIdx) == dropIdx {
			continue
		}
		result, err := pipe.RecvData(dp.blockID, dp.pktIdx, dp.data)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, result...)
	}

	// Packets before the gap (0,1) delivered; packets after (3,4) waiting.
	if len(all) != dropIdx {
		t.Errorf("expected %d frames before repair (before gap), got %d", dropIdx, len(all))
	}

	// Feed repair — should recover pkt2 and flush 2,3,4.
	for _, rp := range repairPkts {
		result, err := pipe.RecvRepair(rp.blockID, rp.repairIdx, 0, 0, rp.data)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, result...)
	}

	if len(all) != K {
		t.Fatalf("expected %d frames total after repair, got %d", K, len(all))
	}
	// Verify the recovered frame.
	orig := originals[dropIdx]
	rec := all[dropIdx]
	if len(rec) < len(orig) {
		t.Errorf("recovered[%d] too short: got %d, want >= %d", dropIdx, len(rec), len(orig))
	} else if !bytes.Equal(rec[:len(orig)], orig) {
		t.Errorf("recovered[%d] prefix mismatch", dropIdx)
	}
}

// TestPipe_SendRecv_MultipleBlocks: 15 frames through K=5 R=1 pipe → 3 blocks.
func TestPipe_SendRecv_MultipleBlocks(t *testing.T) {
	const K, R, N = 5, 1, 15

	type dataPkt struct {
		blockID uint32
		pktIdx  uint16
		data    []byte
	}
	type repairPkt struct {
		blockID   uint32
		repairIdx uint8
		data      []byte
	}

	var dataQ []dataPkt
	var repairQ []repairPkt

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			dataQ = append(dataQ, dataPkt{blockID, pktIdx, cp})
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			repairQ = append(repairQ, repairPkt{blockID, repairIdx, cp})
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	originals := makeFrames(N)
	for _, f := range originals {
		if err := pipe.Send(f); err != nil {
			t.Fatal(err)
		}
	}

	if len(dataQ) != N {
		t.Fatalf("expected %d data packets, got %d", N, len(dataQ))
	}
	expectedBlocks := N / K
	if len(repairQ) != expectedBlocks*R {
		t.Fatalf("expected %d repair packets, got %d", expectedBlocks*R, len(repairQ))
	}

	// Replay all data; collect all delivered frames.
	var all [][]byte
	for _, dp := range dataQ {
		result, err := pipe.RecvData(dp.blockID, dp.pktIdx, dp.data)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, result...)
	}

	if len(all) != N {
		t.Fatalf("expected %d frames, got %d", N, len(all))
	}
	for i, orig := range originals {
		rec := all[i]
		if len(rec) < len(orig) {
			t.Errorf("frame %d too short: got %d, want >= %d", i, len(rec), len(orig))
		} else if !bytes.Equal(rec[:len(orig)], orig) {
			t.Errorf("frame %d mismatch", i)
		}
	}
}

// TestPipe_RepairCallback_CalledOnce: exactly one repair callback for K=5 R=1.
func TestPipe_RepairCallback_CalledOnce(t *testing.T) {
	const K, R = 5, 1

	repairCount := 0
	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error { return nil },
		func(blockID uint32, repairIdx uint8, data []byte) error {
			repairCount++
			if repairIdx != 0 {
				t.Errorf("repairIdx should be 0 for R=1, got %d", repairIdx)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range makeFrames(K) {
		if err := pipe.Send(f); err != nil {
			t.Fatal(err)
		}
	}

	if repairCount != 1 {
		t.Fatalf("sendRepair called %d times, want 1", repairCount)
	}
}

// TestPipe_SendRepairNil_NoLoss: nil sendRepair should not panic.
func TestPipe_SendRepairNil_NoLoss(t *testing.T) {
	const K, R = 5, 1

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error { return nil },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range makeFrames(K) {
		if err := pipe.Send(f); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPipe_RecvData_WrongBlockID: stale block IDs should be silently ignored.
func TestPipe_RecvData_WrongBlockID(t *testing.T) {
	const K, R = 5, 1

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error { return nil },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	data := makeFrames(1)[0]
	for i := 0; i < (maxOldBlocks+2)*K; i++ {
		pipe.Send(data)
	}

	result, err := pipe.RecvData(0, 0, data)
	if err != nil {
		t.Fatalf("unexpected error for stale block: %v", err)
	}
	_ = result
}

// TestPipe_RS_TwoLoss: K=5, R=2, drop 2 data packets, verify RS recovery.
// Packet 0 (before first gap) is streamed immediately; rest delivered after repair.
func TestPipe_RS_TwoLoss(t *testing.T) {
	const K, R = 5, 2

	type dataPkt struct {
		blockID uint32
		pktIdx  uint16
		data    []byte
	}
	type repairPkt struct {
		blockID   uint32
		repairIdx uint8
		data      []byte
	}

	var dataQ []dataPkt
	var repairQ []repairPkt

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			dataQ = append(dataQ, dataPkt{blockID, pktIdx, cp})
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			repairQ = append(repairQ, repairPkt{blockID, repairIdx, cp})
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	originals := makeFrames(K)
	for _, f := range originals {
		if err := pipe.Send(f); err != nil {
			t.Fatal(err)
		}
	}

	if len(repairQ) != R {
		t.Fatalf("expected %d repair symbols, got %d", R, len(repairQ))
	}

	// Drop pktIdx 1 and 3. Pkt 0 delivered streaming; pkts 2,4 stuck behind gap at 1.
	dropSet := map[int]bool{1: true, 3: true}

	var all [][]byte
	for _, dp := range dataQ {
		if dropSet[int(dp.pktIdx)] {
			continue
		}
		result, err := pipe.RecvData(dp.blockID, dp.pktIdx, dp.data)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, result...)
	}

	// Feed both repair symbols; RS recovers 1 and 3, then flushes 1,2,3,4.
	for _, rp := range repairQ {
		result, err := pipe.RecvRepair(rp.blockID, rp.repairIdx, K, R, rp.data)
		if err != nil {
			t.Fatalf("RecvRepair error: %v", err)
		}
		all = append(all, result...)
	}

	if len(all) != K {
		t.Fatalf("expected %d frames total, got %d", K, len(all))
	}
	for i, orig := range originals {
		rec := all[i]
		if len(rec) < len(orig) {
			t.Errorf("frame %d too short after RS recovery: got %d, want >= %d", i, len(rec), len(orig))
		} else if !bytes.Equal(rec[:len(orig)], orig) {
			t.Errorf("frame %d mismatch after RS recovery", i)
		}
	}
}
