package fec

import (
	"bytes"
	"math/rand"
	"testing"
)

// makePackets generates n packets of the given size with deterministic pseudo-random content.
func makePackets(n, size int) [][]byte {
	rng := rand.New(rand.NewSource(42))
	pkts := make([][]byte, n)
	for i := range pkts {
		pkts[i] = make([]byte, size)
		rng.Read(pkts[i])
	}
	return pkts
}

// makeVarPackets generates n packets with varying sizes (size to size*2).
func makeVarPackets(n, baseSize int) [][]byte {
	rng := rand.New(rand.NewSource(99))
	pkts := make([][]byte, n)
	for i := range pkts {
		sz := baseSize + rng.Intn(baseSize+1)
		pkts[i] = make([]byte, sz)
		rng.Read(pkts[i])
	}
	return pkts
}

// encodeBlock encodes k packets through the encoder and returns (originals, repairs, blockID).
func encodeBlock(t *testing.T, k, r int, pkts [][]byte) (originals [][]byte, repairs [][]byte, blockID uint32) {
	t.Helper()
	enc, err := NewEncoder(k, r)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	for _, p := range pkts {
		rep := enc.Add(p)
		if rep != nil {
			repairs = rep
			blockID = enc.BlockID() - 1
		}
	}
	return pkts, repairs, blockID
}

// TestEncoderDecoder_NoLoss: encode K packets, receive all, verify decode succeeds.
func TestEncoderDecoder_NoLoss(t *testing.T) {
	const k, r = 4, 1
	originals := makePackets(k, 100)

	enc, err := NewEncoder(k, r)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	dec, err := NewDecoder(k, r)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	var blockID uint32
	var repairs [][]byte
	for i, p := range originals {
		rep := enc.Add(p)
		if rep != nil {
			repairs = rep
			blockID = enc.BlockID() - 1
		}
		// feed all data packets to decoder
		result, err := dec.AddData(blockID, i, p)
		if err != nil {
			t.Fatalf("AddData[%d]: %v", i, err)
		}
		if i == k-1 {
			// last packet — should complete block
			if result == nil {
				t.Fatal("expected complete block after all data packets")
			}
			for j, orig := range originals {
				if !bytes.Equal(result[j], orig) {
					t.Errorf("packet %d mismatch", j)
				}
			}
		}
		_ = repairs
	}
}

// TestEncoderDecoder_OneLoss: drop 1 data packet, verify XOR repair recovers it.
func TestEncoderDecoder_OneLoss(t *testing.T) {
	const k, r = 8, 1
	originals := makePackets(k, 200)

	for dropIdx := 0; dropIdx < k; dropIdx++ {
		t.Run("drop"+string(rune('0'+dropIdx)), func(t *testing.T) {
			enc, _ := NewEncoder(k, r)
			dec, _ := NewDecoder(k, r)

			var blockID uint32
			var repairs [][]byte

			for _, p := range originals {
				rep := enc.Add(p)
				if rep != nil {
					repairs = rep
					blockID = enc.BlockID() - 1
				}
			}

			// Feed all data packets except dropIdx
			for i, p := range originals {
				if i == dropIdx {
					continue
				}
				result, err := dec.AddData(blockID, i, p)
				if err != nil {
					t.Fatalf("AddData: %v", err)
				}
				if result != nil {
					t.Fatal("should not complete without repair when a packet is missing")
				}
			}

			// Feed repair symbol — should trigger recovery
			result, err := dec.AddRepair(blockID, 0, repairs[0])
			if err != nil {
				t.Fatalf("AddRepair: %v", err)
			}
			if result == nil {
				t.Fatal("expected recovery after repair symbol")
			}
			for i, orig := range originals {
				if !bytes.Equal(result[i], orig) {
					t.Errorf("packet %d mismatch after recovery of drop %d", i, dropIdx)
				}
			}
		})
	}
}

// TestEncoderDecoder_TwoLoss_RS: R=2, drop any 2 of K, verify RS recovery.
func TestEncoderDecoder_TwoLoss_RS(t *testing.T) {
	const k, r = 6, 2
	originals := makePackets(k, 150)

	dropPairs := [][2]int{{0, 1}, {0, k - 1}, {k/2 - 1, k/2}, {k - 2, k - 1}}

	for _, pair := range dropPairs {
		pair := pair
		t.Run("drop_recovery", func(t *testing.T) {
			enc, err := NewEncoder(k, r)
			if err != nil {
				t.Fatalf("NewEncoder: %v", err)
			}
			dec, err := NewDecoder(k, r)
			if err != nil {
				t.Fatalf("NewDecoder: %v", err)
			}

			var blockID uint32
			var repairs [][]byte
			for _, p := range originals {
				rep := enc.Add(p)
				if rep != nil {
					repairs = rep
					blockID = enc.BlockID() - 1
				}
			}

			dropSet := map[int]bool{pair[0]: true, pair[1]: true}

			for i, p := range originals {
				if dropSet[i] {
					continue
				}
				result, err := dec.AddData(blockID, i, p)
				if err != nil {
					t.Fatalf("AddData[%d]: %v", i, err)
				}
				if result != nil {
					t.Fatal("should not complete prematurely")
				}
			}

			// Feed both repair symbols
			var result [][]byte
			for ri, rep := range repairs {
				var err error
				result, err = dec.AddRepair(blockID, ri, rep)
				if err != nil {
					t.Fatalf("AddRepair[%d]: %v", ri, err)
				}
			}

			if result == nil {
				t.Fatal("expected recovery after 2 repair symbols")
			}
			for i, orig := range originals {
				if !bytes.Equal(result[i], orig) {
					t.Errorf("packet %d mismatch (drop pair %v)", i, pair)
				}
			}
		})
	}
}

// TestEncoderDecoder_TooManyLosses: drop more than R, verify ErrUnrecoverable or nil (no panic).
func TestEncoderDecoder_TooManyLosses(t *testing.T) {
	const k, r = 6, 1
	originals := makePackets(k, 100)

	enc, _ := NewEncoder(k, r)
	dec, _ := NewDecoder(k, r)

	var blockID uint32
	var repairs [][]byte
	for _, p := range originals {
		rep := enc.Add(p)
		if rep != nil {
			repairs = rep
			blockID = enc.BlockID() - 1
		}
	}

	// Drop two packets — with R=1, unrecoverable
	for i, p := range originals {
		if i == 0 || i == 1 {
			continue
		}
		_, _ = dec.AddData(blockID, i, p)
	}

	// Feed repair — should return ErrUnrecoverable (not panic)
	_, err := dec.AddRepair(blockID, 0, repairs[0])
	if err != nil && err != ErrUnrecoverable {
		t.Fatalf("unexpected error: %v (want nil or ErrUnrecoverable)", err)
	}
	// Either nil (waiting) or ErrUnrecoverable is acceptable; must not panic
}

// TestEncoderDecoder_OutOfOrder: deliver repair before data, verify still recovers.
func TestEncoderDecoder_OutOfOrder(t *testing.T) {
	const k, r = 5, 1
	originals := makePackets(k, 80)

	enc, _ := NewEncoder(k, r)
	dec, _ := NewDecoder(k, r)

	var blockID uint32
	var repairs [][]byte
	for _, p := range originals {
		rep := enc.Add(p)
		if rep != nil {
			repairs = rep
			blockID = enc.BlockID() - 1
		}
	}

	const dropIdx = 2

	// Feed repair FIRST (out of order)
	result, err := dec.AddRepair(blockID, 0, repairs[0])
	if err != nil {
		t.Fatalf("AddRepair early: %v", err)
	}
	if result != nil {
		t.Fatal("should not complete with only repair")
	}

	// Now feed all data packets except the dropped one
	for i, p := range originals {
		if i == dropIdx {
			continue
		}
		result, err = dec.AddData(blockID, i, p)
		if err != nil {
			t.Fatalf("AddData[%d]: %v", i, err)
		}
	}

	if result == nil {
		t.Fatal("expected recovery after all packets + repair (out of order)")
	}
	for i, orig := range originals {
		if !bytes.Equal(result[i], orig) {
			t.Errorf("packet %d mismatch", i)
		}
	}
}

// TestEncoder_MultipleBlocks: run 3 full blocks through encoder, verify correct blockIDs.
func TestEncoder_MultipleBlocks(t *testing.T) {
	const k, r, numBlocks = 4, 1, 3
	enc, err := NewEncoder(k, r)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}

	rng := rand.New(rand.NewSource(7))
	for block := 0; block < numBlocks; block++ {
		var gotRepairs [][]byte
		var repairBlockID uint32
		for i := 0; i < k; i++ {
			pkt := make([]byte, 64)
			rng.Read(pkt)
			rep := enc.Add(pkt)
			if rep != nil {
				gotRepairs = rep
				repairBlockID = enc.BlockID() - 1
			}
		}
		if gotRepairs == nil {
			t.Errorf("block %d: expected repair symbols", block)
		}
		if repairBlockID != uint32(block) {
			t.Errorf("block %d: got blockID %d", block, repairBlockID)
		}
	}

	if enc.BlockID() != numBlocks {
		t.Errorf("expected BlockID=%d, got %d", numBlocks, enc.BlockID())
	}
}

// TestXorAll_Correctness: xorAll then xorRecover gives back original.
func TestXorAll_Correctness(t *testing.T) {
	const n = 10
	pkts := makePackets(n, 128)

	parity := xorAll(pkts)

	for dropIdx := 0; dropIdx < n; dropIdx++ {
		data := make([][]byte, n)
		copy(data, pkts)
		data[dropIdx] = nil

		result, err := xorRecover(data, parity, n)
		if err != nil {
			t.Fatalf("xorRecover drop=%d: %v", dropIdx, err)
		}
		if !bytes.Equal(result[dropIdx], pkts[dropIdx]) {
			t.Errorf("drop=%d: recovered mismatch", dropIdx)
		}
	}
}

// TestXorAll_VariableLengths: XOR parity + recovery works with variable-length packets.
// The recovered packet may be padded to parity length with trailing zeros, so we check
// that the original content is a prefix of the recovered data (the transport layer
// knows the original length from the outer frame header).
func TestXorAll_VariableLengths(t *testing.T) {
	pkts := makeVarPackets(8, 50)
	parity := xorAll(pkts)

	for dropIdx := 0; dropIdx < len(pkts); dropIdx++ {
		data := make([][]byte, len(pkts))
		copy(data, pkts)
		data[dropIdx] = nil

		result, err := xorRecover(data, parity, len(pkts))
		if err != nil {
			t.Fatalf("drop=%d: %v", dropIdx, err)
		}
		orig := pkts[dropIdx]
		recovered := result[dropIdx]
		// Recovered may be longer (padded with zeros) but must start with the original bytes.
		if len(recovered) < len(orig) {
			t.Errorf("drop=%d: recovered too short: got %d, want >= %d", dropIdx, len(recovered), len(orig))
			continue
		}
		if !bytes.Equal(recovered[:len(orig)], orig) {
			t.Errorf("drop=%d: recovered prefix mismatch (variable lengths)", dropIdx)
		}
		// Trailing bytes beyond original length should be zero (XOR with zero-padded sources)
		for i := len(orig); i < len(recovered); i++ {
			if recovered[i] != 0 {
				t.Errorf("drop=%d: non-zero trailing byte at %d", dropIdx, i)
			}
		}
	}
}

// TestDecoder_OldBlocksExpired: blocks far behind maxSeen are dropped.
func TestDecoder_OldBlocksExpired(t *testing.T) {
	const k, r = 4, 1
	dec, _ := NewDecoder(k, r)

	// Add one packet for block 0 — incomplete, should be buffered
	_, _ = dec.AddData(0, 0, []byte("hello"))

	// Advance maxSeen past maxOldBlocks threshold
	for id := uint32(1); id <= uint32(maxOldBlocks)+2; id++ {
		_, _ = dec.AddData(id, 0, []byte("x"))
	}

	dec.mu.Lock()
	_, exists := dec.blocks[0]
	dec.mu.Unlock()

	if exists {
		t.Error("block 0 should have been expired")
	}
}
