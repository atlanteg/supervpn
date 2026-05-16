package fec

import (
	"testing"
)

const benchPacketSize = 1200 // typical VPN MTU

// makeBenchPackets generates n fixed-size packets for benchmark setup.
func makeBenchPackets(n, size int) [][]byte {
	pkts := make([][]byte, n)
	for i := range pkts {
		p := make([]byte, size)
		for j := range p {
			p[j] = byte(i*7 + j*3)
		}
		pkts[i] = p
	}
	return pkts
}

// BenchmarkEncoder_K20R1 measures Encoder.Add throughput for K=20, R=1 (XOR path).
// Reports MB/s based on (K * packetSize) bytes per completed block.
func BenchmarkEncoder_K20R1(b *testing.B) {
	const k, r = 20, 1
	pkts := makeBenchPackets(k, benchPacketSize)
	b.SetBytes(int64(benchPacketSize * k))
	b.ReportAllocs()

	enc, err := NewEncoder(k, r)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range pkts {
			enc.Add(p)
		}
	}
}

// BenchmarkEncoder_K20R2 measures Encoder.Add throughput for K=20, R=2 (RS path).
func BenchmarkEncoder_K20R2(b *testing.B) {
	const k, r = 20, 2
	pkts := makeBenchPackets(k, benchPacketSize)
	b.SetBytes(int64(benchPacketSize * k))
	b.ReportAllocs()

	enc, err := NewEncoder(k, r)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range pkts {
			enc.Add(p)
		}
	}
}

// BenchmarkEncoder_K50R2 measures Encoder.Add throughput for K=50, R=2 (larger block, RS path).
func BenchmarkEncoder_K50R2(b *testing.B) {
	const k, r = 50, 2
	pkts := makeBenchPackets(k, benchPacketSize)
	b.SetBytes(int64(benchPacketSize * k))
	b.ReportAllocs()

	enc, err := NewEncoder(k, r)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range pkts {
			enc.Add(p)
		}
	}
}

// BenchmarkDecoder_NoLoss_K20R1 measures decoder throughput when all K data packets arrive
// (no recovery needed — just counting and returning the block).
func BenchmarkDecoder_NoLoss_K20R1(b *testing.B) {
	const k, r = 20, 1
	pkts := makeBenchPackets(k, benchPacketSize)
	b.SetBytes(int64(benchPacketSize * k))
	b.ReportAllocs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec, err := NewDecoder(k, r)
		if err != nil {
			b.Fatal(err)
		}
		blockID := uint32(i)
		for idx, p := range pkts {
			dec.AddData(blockID, idx, p) //nolint:errcheck
		}
	}
}

// BenchmarkDecoder_OneLoss_K20R1 measures decoder throughput with 1 loss requiring XOR recovery.
// Setup: encode a block, drop packet at idx K/2, feed K-1 data + 1 repair.
func BenchmarkDecoder_OneLoss_K20R1(b *testing.B) {
	const k, r = 20, 1
	const dropIdx = k / 2
	pkts := makeBenchPackets(k, benchPacketSize)

	// Pre-compute repairs outside the benchmark loop.
	enc, err := NewEncoder(k, r)
	if err != nil {
		b.Fatal(err)
	}
	var repairs [][]byte
	for _, p := range pkts {
		if rep := enc.Add(p); rep != nil {
			repairs = rep
		}
	}

	b.SetBytes(int64(benchPacketSize * k))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dec, err := NewDecoder(k, r)
		if err != nil {
			b.Fatal(err)
		}
		blockID := uint32(i)
		for idx, p := range pkts {
			if idx == dropIdx {
				continue
			}
			dec.AddData(blockID, idx, p) //nolint:errcheck
		}
		dec.AddRepair(blockID, 0, repairs[0]) //nolint:errcheck
	}
}

// BenchmarkDecoder_TwoLoss_K20R2 measures RS recovery of 2 losses in a K=20, R=2 block.
func BenchmarkDecoder_TwoLoss_K20R2(b *testing.B) {
	const k, r = 20, 2
	const drop0, drop1 = 5, 15
	pkts := makeBenchPackets(k, benchPacketSize)

	enc, err := NewEncoder(k, r)
	if err != nil {
		b.Fatal(err)
	}
	var repairs [][]byte
	for _, p := range pkts {
		if rep := enc.Add(p); rep != nil {
			repairs = rep
		}
	}

	b.SetBytes(int64(benchPacketSize * k))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dec, err := NewDecoder(k, r)
		if err != nil {
			b.Fatal(err)
		}
		blockID := uint32(i)
		for idx, p := range pkts {
			if idx == drop0 || idx == drop1 {
				continue
			}
			dec.AddData(blockID, idx, p) //nolint:errcheck
		}
		for ri, rep := range repairs {
			dec.AddRepair(blockID, ri, rep) //nolint:errcheck
		}
	}
}

// BenchmarkPipe_Roundtrip_K20R1 measures full send→recv round-trip through Pipe with no loss.
func BenchmarkPipe_Roundtrip_K20R1(b *testing.B) {
	const k, r = 20, 1
	frame := make([]byte, benchPacketSize)
	for i := range frame {
		frame[i] = byte(i)
	}
	b.SetBytes(int64(benchPacketSize * k))
	b.ReportAllocs()

	// Create a receiver pipe (no send callbacks needed — we call RecvData directly).
	recvPipe, err := NewPipe(k, r, 0, func(uint32, uint16, []byte) error { return nil }, nil)
	if err != nil {
		b.Fatal(err)
	}

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

	senderPipe, err := NewPipe(k, r, 0,
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
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dataQ = dataQ[:0]
		repairQ = repairQ[:0]

		// Send one full block (k frames).
		for j := 0; j < k; j++ {
			if err := senderPipe.Send(frame); err != nil {
				b.Fatal(err)
			}
		}

		// Receive all data packets.
		for _, dp := range dataQ {
			recvPipe.RecvData(dp.blockID, dp.pktIdx, dp.data) //nolint:errcheck
		}
		// Receive repair packets.
		for _, rp := range repairQ {
			recvPipe.RecvRepair(rp.blockID, rp.repairIdx, uint8(k), uint8(r), rp.data) //nolint:errcheck
		}
	}
}

// BenchmarkXorAll measures raw XOR of 20 × 1200-byte packets.
func BenchmarkXorAll(b *testing.B) {
	const n = 20
	pkts := makeBenchPackets(n, benchPacketSize)
	b.SetBytes(int64(benchPacketSize * n))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		xorAll(pkts)
	}
}

// BenchmarkRSEncode_K20R2 measures raw rsEncode for K=20, R=2, 1200-byte shards.
func BenchmarkRSEncode_K20R2(b *testing.B) {
	const k, r = 20, 2
	pkts := makeBenchPackets(k, benchPacketSize)
	b.SetBytes(int64(benchPacketSize * k))
	b.ReportAllocs()

	enc, err := NewEncoder(k, r)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rsEncode(enc.enc, pkts, k, r)
	}
}
