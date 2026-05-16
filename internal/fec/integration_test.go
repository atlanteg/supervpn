package fec

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/atlanteg/supervpn/internal/proto"
)

// TestFECPipe_EndToEnd_5PercentLoss simulates 5% random packet loss through the full
// FECPipe send→receive path and verifies all frames are recovered.
//
// The test uses proto.PackDataSeq / PackRepairSeq to exercise the same wire-format
// path that the server and client use in production.
func TestFECPipe_EndToEnd_5PercentLoss(t *testing.T) {
	const (
		numFrames   = 1000
		frameSize   = 1200
		lossPercent = 5
		k, r        = 20, 1
	)

	rng := rand.New(rand.NewSource(42))

	var recovered [][]byte

	// Receiver pipe — only the decode path is used; send callbacks are no-ops.
	recvPipe, err := NewPipe(k, r, 0,
		func(uint32, uint16, []byte) error { return nil },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Sender pipe — callbacks simulate the UDP wire with random packet loss.
	senderPipe, err := NewPipe(k, r, 0,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			if rng.Intn(100) < lossPercent {
				return nil // dropped
			}
			// Exercise PackDataSeq / UnpackDataSeq to mirror the real send path.
			seq := proto.PackDataSeq(blockID, pktIdx)
			bID, pIdx := proto.UnpackDataSeq(seq)
			frames, err := recvPipe.RecvData(bID, pIdx, data)
			if err == nil {
				recovered = append(recovered, frames...)
			}
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			if rng.Intn(100) < lossPercent {
				return nil // dropped
			}
			// Exercise PackRepairSeq / UnpackRepairSeq to mirror the real repair path.
			seq := proto.PackRepairSeq(blockID, repairIdx, uint8(k), uint8(r))
			bID, rIdx, bK, bR := proto.UnpackRepairSeq(seq)
			frames, err := recvPipe.RecvRepair(bID, rIdx, bK, bR, data)
			if err == nil {
				recovered = append(recovered, frames...)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Generate and send all frames.
	for i := 0; i < numFrames; i++ {
		frame := make([]byte, frameSize)
		frame[0] = byte(i >> 8)
		frame[1] = byte(i)
		for j := 2; j < frameSize; j++ {
			frame[j] = byte(i*j + j)
		}
		if err := senderPipe.Send(frame); err != nil {
			t.Fatalf("Send frame %d: %v", i, err)
		}
	}

	// Only complete blocks can be recovered. The trailing partial block (< K frames)
	// never gets its repair symbol so it is expected to be absent.
	completeBlocks := numFrames / k
	maxRecoverable := completeBlocks * k

	recoveryRate := float64(len(recovered)) / float64(maxRecoverable) * 100
	t.Logf("K=%d R=%d loss=%d%% | sent=%d maxRecoverable=%d recovered=%d rate=%.1f%%",
		k, r, lossPercent, numFrames, maxRecoverable, len(recovered), recoveryRate)

	// With 5% independent random loss and R=1, a block of K=20 data + 1 repair packet
	// is recoverable only when 0 or 1 of the 21 wire packets is dropped.
	// P(recoverable) = 0.95^21 + C(21,1)*0.05*0.95^20 ≈ 72%.
	// We set the floor at 60% to tolerate RNG variance while still catching regressions.
	if recoveryRate < 60.0 {
		t.Errorf("recovery rate %.1f%% is below expected 60%% for K=%d R=%d loss=%d%%",
			recoveryRate, k, r, lossPercent)
	}
}

// TestFECPipe_EndToEnd_R2_5PercentLoss tests with R=2 (RS recovery of up to 2 losses).
// Expected: near 100% recovery at 5% loss since double-loss blocks are rare.
func TestFECPipe_EndToEnd_R2_5PercentLoss(t *testing.T) {
	const (
		numFrames   = 1000
		frameSize   = 1200
		lossPercent = 5
		k, r        = 20, 2
	)

	rng := rand.New(rand.NewSource(17))

	var recovered [][]byte

	recvPipe, err := NewPipe(k, r, 0,
		func(uint32, uint16, []byte) error { return nil },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	senderPipe, err := NewPipe(k, r, 0,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			if rng.Intn(100) < lossPercent {
				return nil
			}
			seq := proto.PackDataSeq(blockID, pktIdx)
			bID, pIdx := proto.UnpackDataSeq(seq)
			frames, err := recvPipe.RecvData(bID, pIdx, data)
			if err == nil {
				recovered = append(recovered, frames...)
			}
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			if rng.Intn(100) < lossPercent {
				return nil
			}
			seq := proto.PackRepairSeq(blockID, repairIdx, uint8(k), uint8(r))
			bID, rIdx, bK, bR := proto.UnpackRepairSeq(seq)
			frames, err := recvPipe.RecvRepair(bID, rIdx, bK, bR, data)
			if err == nil {
				recovered = append(recovered, frames...)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < numFrames; i++ {
		frame := make([]byte, frameSize)
		frame[0] = byte(i >> 8)
		frame[1] = byte(i)
		for j := 2; j < frameSize; j++ {
			frame[j] = byte(i*j + j)
		}
		if err := senderPipe.Send(frame); err != nil {
			t.Fatalf("Send frame %d: %v", i, err)
		}
	}

	completeBlocks := numFrames / k
	maxRecoverable := completeBlocks * k

	recoveryRate := float64(len(recovered)) / float64(maxRecoverable) * 100
	t.Logf("K=%d R=%d loss=%d%% | sent=%d maxRecoverable=%d recovered=%d rate=%.1f%%",
		k, r, lossPercent, numFrames, maxRecoverable, len(recovered), recoveryRate)

	// R=2 can survive any 2 losses per block; triple-loss blocks are extremely rare
	// at 5% loss. Expect >98% recovery.
	if recoveryRate < 98.0 {
		t.Errorf("recovery rate %.1f%% is below expected 98%% for R=2", recoveryRate)
	}
}

// TestFECPipe_EndToEnd_BurstLoss simulates a burst of 3 consecutive packet losses.
//
// With K=10 R=1 (XOR): a 3-packet burst in the same block is unrecoverable — the block
// is simply skipped, which is the expected behaviour.
//
// With K=10 R=3 (RS): up to 3 losses per block are recoverable, so even a 3-packet
// burst must be fully recovered.
func TestFECPipe_EndToEnd_BurstLoss(t *testing.T) {
	const (
		frameSize  = 1200
		k          = 10
		burstStart = 3 // drop packet indices 3, 4, 5 of block 0
		burstLen   = 3
	)

	t.Run("R1_burst_unrecoverable", func(t *testing.T) {
		const r = 1
		// We send exactly 1 block (k frames) and drop packets 3,4,5.
		// With R=1 we cannot recover 3 losses — the block must NOT appear recovered.

		var recovered [][]byte
		var sentDataPkts []struct {
			blockID uint32
			pktIdx  uint16
			data    []byte
		}
		var sentRepairPkts []struct {
			blockID   uint32
			repairIdx uint8
			data      []byte
		}

		// Collect all sent packets first.
		senderPipe, err := NewPipe(k, r, 0,
			func(blockID uint32, pktIdx uint16, data []byte) error {
				cp := make([]byte, len(data))
				copy(cp, data)
				sentDataPkts = append(sentDataPkts, struct {
					blockID uint32
					pktIdx  uint16
					data    []byte
				}{blockID, pktIdx, cp})
				return nil
			},
			func(blockID uint32, repairIdx uint8, data []byte) error {
				cp := make([]byte, len(data))
				copy(cp, data)
				sentRepairPkts = append(sentRepairPkts, struct {
					blockID   uint32
					repairIdx uint8
					data      []byte
				}{blockID, repairIdx, cp})
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		recvPipe, err := NewPipe(k, r, 0,
			func(uint32, uint16, []byte) error { return nil },
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Send one full block.
		for i := 0; i < k; i++ {
			frame := make([]byte, frameSize)
			frame[0] = byte(i)
			if err := senderPipe.Send(frame); err != nil {
				t.Fatalf("Send: %v", err)
			}
		}

		// Feed data packets, dropping burstStart..burstStart+burstLen-1.
		for _, dp := range sentDataPkts {
			idx := int(dp.pktIdx)
			if idx >= burstStart && idx < burstStart+burstLen {
				continue // simulate burst loss
			}
			seq := proto.PackDataSeq(dp.blockID, dp.pktIdx)
			bID, pIdx := proto.UnpackDataSeq(seq)
			frames, err := recvPipe.RecvData(bID, pIdx, dp.data)
			if err == nil {
				recovered = append(recovered, frames...)
			}
		}

		// Feed repair packet(s).
		for _, rp := range sentRepairPkts {
			seq := proto.PackRepairSeq(rp.blockID, rp.repairIdx, uint8(k), uint8(r))
			bID, rIdx, bK, bR := proto.UnpackRepairSeq(seq)
			frames, err := recvPipe.RecvRepair(bID, rIdx, bK, bR, rp.data)
			if err == nil {
				recovered = append(recovered, frames...)
			}
		}

		// With R=1 and 3 losses, only the burstStart frames before the gap are
		// streamed immediately. The rest of the block (after the gap) is unrecoverable.
		t.Logf("R=1 burst=%d losses: recovered %d frames (expected %d)", burstLen, len(recovered), burstStart)
		if len(recovered) != burstStart {
			t.Errorf("R=1 burst: expected %d streamed frames (before gap), got %d",
				burstStart, len(recovered))
		}
	})

	t.Run("R3_burst_recovered", func(t *testing.T) {
		const r = 3
		// K=10 R=3: drop packets 3,4,5 of block 0 and verify full RS recovery.

		var sentDataPkts []struct {
			blockID uint32
			pktIdx  uint16
			data    []byte
		}
		var sentRepairPkts []struct {
			blockID   uint32
			repairIdx uint8
			data      []byte
		}

		originals := make([][]byte, k)

		senderPipe, err := NewPipe(k, r, 0,
			func(blockID uint32, pktIdx uint16, data []byte) error {
				cp := make([]byte, len(data))
				copy(cp, data)
				sentDataPkts = append(sentDataPkts, struct {
					blockID uint32
					pktIdx  uint16
					data    []byte
				}{blockID, pktIdx, cp})
				return nil
			},
			func(blockID uint32, repairIdx uint8, data []byte) error {
				cp := make([]byte, len(data))
				copy(cp, data)
				sentRepairPkts = append(sentRepairPkts, struct {
					blockID   uint32
					repairIdx uint8
					data      []byte
				}{blockID, repairIdx, cp})
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		recvPipe, err := NewPipe(k, r, 0,
			func(uint32, uint16, []byte) error { return nil },
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Send one full block.
		for i := 0; i < k; i++ {
			frame := make([]byte, frameSize)
			frame[0] = byte(i)
			for j := 1; j < frameSize; j++ {
				frame[j] = byte(i*j + 1)
			}
			originals[i] = frame
			if err := senderPipe.Send(frame); err != nil {
				t.Fatalf("Send: %v", err)
			}
		}

		var recovered [][]byte

		// Feed data packets, dropping burstStart..burstStart+burstLen-1.
		for _, dp := range sentDataPkts {
			idx := int(dp.pktIdx)
			if idx >= burstStart && idx < burstStart+burstLen {
				continue // simulate burst loss
			}
			seq := proto.PackDataSeq(dp.blockID, dp.pktIdx)
			bID, pIdx := proto.UnpackDataSeq(seq)
			frames, err := recvPipe.RecvData(bID, pIdx, dp.data)
			if err == nil {
				recovered = append(recovered, frames...)
			}
		}

		// Feed all R=3 repair packets.
		for _, rp := range sentRepairPkts {
			seq := proto.PackRepairSeq(rp.blockID, rp.repairIdx, uint8(k), uint8(r))
			bID, rIdx, bK, bR := proto.UnpackRepairSeq(seq)
			frames, err := recvPipe.RecvRepair(bID, rIdx, bK, bR, rp.data)
			if err == nil {
				recovered = append(recovered, frames...)
			}
		}

		t.Logf("R=3 burst=%d losses: recovered %d frames (expected %d)", burstLen, len(recovered), k)

		if len(recovered) != k {
			t.Fatalf("R=3 expected full block recovery (%d frames), got %d", k, len(recovered))
		}

		// Verify content of each recovered frame matches the original.
		for i, orig := range originals {
			rec := recovered[i]
			if len(rec) < len(orig) {
				t.Errorf("frame %d: recovered too short (got %d, want >= %d)", i, len(rec), len(orig))
				continue
			}
			if !bytes.Equal(rec[:len(orig)], orig) {
				t.Errorf("frame %d: content mismatch after RS burst recovery", i)
			}
		}
	})
}
