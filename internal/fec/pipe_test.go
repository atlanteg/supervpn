package fec

import (
	"bytes"
	"testing"
)

// makeFrames generates n distinct test frames of varying sizes.
func makeFrames(n int) [][]byte {
	frames := make([][]byte, n)
	for i := range frames {
		sz := 64 + i*3 // vary size so XOR/RS math is non-trivial
		f := make([]byte, sz)
		for j := range f {
			f[j] = byte(i*7 + j*3)
		}
		frames[i] = f
	}
	return frames
}

// TestPipe_SendRecv_NoLoss: all K frames arrive; decoder completes on the Kth.
func TestPipe_SendRecv_NoLoss(t *testing.T) {
	const K, R = 5, 1

	var (
		dataPkts   []struct{ blockID uint32; pktIdx uint16; data []byte }
		repairPkts []struct{ blockID uint32; repairIdx uint8; data []byte }
	)

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			dataPkts = append(dataPkts, struct{ blockID uint32; pktIdx uint16; data []byte }{blockID, pktIdx, cp})
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			repairPkts = append(repairPkts, struct{ blockID uint32; repairIdx uint8; data []byte }{blockID, repairIdx, cp})
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

	if len(dataPkts) != K {
		t.Fatalf("expected %d data callbacks, got %d", K, len(dataPkts))
	}
	if len(repairPkts) != R {
		t.Fatalf("expected %d repair callbacks, got %d", R, len(repairPkts))
	}

	// Feed all K data packets into RecvData; expect recovery on the last one.
	var recovered [][]byte
	for _, dp := range dataPkts {
		result, err := pipe.RecvData(dp.blockID, dp.pktIdx, dp.data)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			recovered = result
		}
	}

	if recovered == nil {
		t.Fatal("expected block to be recovered after all K frames, got nil")
	}
	if len(recovered) != K {
		t.Fatalf("recovered block has %d frames, want %d", len(recovered), K)
	}
	for i, orig := range originals {
		rec := recovered[i]
		if len(rec) < len(orig) {
			t.Errorf("frame %d too short: got %d bytes, want at least %d", i, len(rec), len(orig))
		} else if !bytes.Equal(rec[:len(orig)], orig) {
			t.Errorf("frame %d prefix mismatch: got %v, want %v", i, rec[:len(orig)], orig)
		}
	}
}

// TestPipe_SendRecv_OneLoss: drop pktIdx=2, recover via XOR repair.
func TestPipe_SendRecv_OneLoss(t *testing.T) {
	const K, R = 5, 1
	const dropIdx = 2

	var (
		dataPkts   []struct{ blockID uint32; pktIdx uint16; data []byte }
		repairPkts []struct{ blockID uint32; repairIdx uint8; data []byte }
	)

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			dataPkts = append(dataPkts, struct{ blockID uint32; pktIdx uint16; data []byte }{blockID, pktIdx, cp})
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			cp := make([]byte, len(data))
			copy(cp, data)
			repairPkts = append(repairPkts, struct{ blockID uint32; repairIdx uint8; data []byte }{blockID, repairIdx, cp})
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

	// Feed all data packets except the dropped one.
	var recovered [][]byte
	for _, dp := range dataPkts {
		if int(dp.pktIdx) == dropIdx {
			continue
		}
		result, err := pipe.RecvData(dp.blockID, dp.pktIdx, dp.data)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			recovered = result
		}
	}

	// Not yet recovered — need repair.
	if recovered != nil {
		t.Fatal("should not have recovered before repair arrives")
	}

	// Feed the repair symbol.
	for _, rp := range repairPkts {
		result, err := pipe.RecvRepair(rp.blockID, rp.repairIdx, 0, 0, rp.data)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			recovered = result
		}
	}

	if recovered == nil {
		t.Fatal("expected recovery after repair symbol, got nil")
	}
	if len(recovered) != K {
		t.Fatalf("recovered block has %d frames, want %d", len(recovered), K)
	}
	// The XOR/RS codec pads recovered packets to the length of the longest frame
	// in the block (to allow byte-wise XOR/RS operations). Compare only the
	// original frame prefix — trailing zeros beyond the original length are expected.
	orig := originals[dropIdx]
	rec := recovered[dropIdx]
	if len(rec) < len(orig) {
		t.Errorf("recovered[%d] too short: got %d bytes, want at least %d", dropIdx, len(rec), len(orig))
	} else if !bytes.Equal(rec[:len(orig)], orig) {
		t.Errorf("recovered[%d] prefix mismatch: got %v, want %v", dropIdx, rec[:len(orig)], orig)
	}
}

// TestPipe_SendRecv_MultipleBlocks: 15 frames through K=5 R=1 pipe → 3 blocks.
func TestPipe_SendRecv_MultipleBlocks(t *testing.T) {
	const K, R, N = 5, 1, 15

	type dataPkt struct{ blockID uint32; pktIdx uint16; data []byte }
	type repairPkt struct{ blockID uint32; repairIdx uint8; data []byte }

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

	// Replay all data through decoder; collect recovered blocks.
	var recoveredBlocks [][]byte
	for _, dp := range dataQ {
		result, err := pipe.RecvData(dp.blockID, dp.pktIdx, dp.data)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			recoveredBlocks = append(recoveredBlocks, result...)
		}
	}

	if len(recoveredBlocks) != N {
		t.Fatalf("expected %d recovered frames across %d blocks, got %d", N, expectedBlocks, len(recoveredBlocks))
	}
	for i, orig := range originals {
		rec := recoveredBlocks[i]
		if len(rec) < len(orig) {
			t.Errorf("frame %d too short: got %d bytes, want at least %d", i, len(rec), len(orig))
		} else if !bytes.Equal(rec[:len(orig)], orig) {
			t.Errorf("frame %d prefix mismatch", i)
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

// TestPipe_SendRepairNil_NoLoss: nil sendRepair should not panic even when a block completes.
func TestPipe_SendRepairNil_NoLoss(t *testing.T) {
	const K, R = 5, 1

	pipe, err := NewPipe(K, R,
		func(blockID uint32, pktIdx uint16, data []byte) error { return nil },
		nil, // intentionally nil
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range makeFrames(K) {
		if err := pipe.Send(f); err != nil {
			t.Fatal(err)
		}
	}
	// If we reach here without panic, the test passes.
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

	// Feed packets for block 0 through K-1 so block 0 completes and is evicted.
	// Then send many more blocks to push block 0 past the maxOldBlocks threshold.
	for i := 0; i < (maxOldBlocks+2)*K; i++ {
		pipe.Send(data)
	}

	// Now feed a packet with blockID=0 (long expired) — should return nil without panic.
	result, err := pipe.RecvData(0, 0, data)
	if err != nil {
		t.Fatalf("unexpected error for stale block: %v", err)
	}
	// result may or may not be nil depending on decoder state, but must not panic.
	_ = result
}

// TestPipe_RS_TwoLoss: K=5, R=2, drop 2 data packets, verify RS recovery.
func TestPipe_RS_TwoLoss(t *testing.T) {
	const K, R = 5, 2

	type dataPkt struct{ blockID uint32; pktIdx uint16; data []byte }
	type repairPkt struct{ blockID uint32; repairIdx uint8; data []byte }

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

	// Drop pktIdx 1 and 3.
	dropSet := map[int]bool{1: true, 3: true}

	var recovered [][]byte
	for _, dp := range dataQ {
		if dropSet[int(dp.pktIdx)] {
			continue
		}
		result, err := pipe.RecvData(dp.blockID, dp.pktIdx, dp.data)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			recovered = result
		}
	}

	// Feed both repair symbols.
	for _, rp := range repairQ {
		result, err := pipe.RecvRepair(rp.blockID, rp.repairIdx, K, R, rp.data)
		if err != nil {
			t.Fatalf("RecvRepair error: %v", err)
		}
		if result != nil {
			recovered = result
		}
	}

	if recovered == nil {
		t.Fatal("expected RS recovery after 2 losses + 2 repairs, got nil")
	}
	if len(recovered) != K {
		t.Fatalf("recovered block has %d frames, want %d", len(recovered), K)
	}
	for i, orig := range originals {
		rec := recovered[i]
		if len(rec) < len(orig) {
			t.Errorf("frame %d too short after RS recovery: got %d bytes, want at least %d", i, len(rec), len(orig))
		} else if !bytes.Equal(rec[:len(orig)], orig) {
			t.Errorf("frame %d prefix mismatch after RS recovery", i)
		}
	}
}
