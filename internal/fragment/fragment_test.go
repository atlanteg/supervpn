package fragment

import (
	"bytes"
	"testing"
	"time"
)

func makeFrame(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

func TestSplit_FitsInOne(t *testing.T) {
	f := makeFrame(1000)
	pieces := Split(f, 1400)
	if len(pieces) != 1 || !bytes.Equal(pieces[0], f) {
		t.Fatalf("frame that fits must be a single unchanged piece, got %d pieces", len(pieces))
	}
	if NeedsSplit(f, 1400) {
		t.Fatal("1000-byte frame should not need split at 1400")
	}
}

func TestSplit_Oversized(t *testing.T) {
	f := makeFrame(1514)
	pieces := Split(f, 1400)
	if len(pieces) != 2 {
		t.Fatalf("1514/1400 must be 2 pieces, got %d", len(pieces))
	}
	if len(pieces[0]) != 1400 || len(pieces[1]) != 114 {
		t.Fatalf("unexpected piece sizes %d/%d", len(pieces[0]), len(pieces[1]))
	}
	// Concatenation must equal the original.
	joined := append(append([]byte{}, pieces[0]...), pieces[1]...)
	if !bytes.Equal(joined, f) {
		t.Fatal("pieces do not reassemble to original")
	}
}

func TestReassemble_RoundTrip(t *testing.T) {
	f := makeFrame(4000)
	pieces := Split(f, 1400) // 3 pieces
	r := NewReassembler()
	var out []byte
	for i, p := range pieces {
		got := r.Add(42, uint8(i), uint8(len(pieces)), p)
		if i < len(pieces)-1 && got != nil {
			t.Fatalf("piece %d completed early", i)
		}
		if i == len(pieces)-1 {
			out = got
		}
	}
	if !bytes.Equal(out, f) {
		t.Fatal("reassembled frame != original")
	}
}

func TestReassemble_OutOfOrderAndDuplicate(t *testing.T) {
	f := makeFrame(3000)
	pieces := Split(f, 1400) // 3 pieces
	r := NewReassembler()

	// Deliver out of order: 2, 0, (dup 2), 1.
	if r.Add(7, 2, 3, pieces[2]) != nil {
		t.Fatal("should not complete on first piece")
	}
	if r.Add(7, 0, 3, pieces[0]) != nil {
		t.Fatal("should not complete yet")
	}
	if r.Add(7, 2, 3, pieces[2]) != nil {
		t.Fatal("duplicate must be ignored, not complete")
	}
	out := r.Add(7, 1, 3, pieces[1])
	if !bytes.Equal(out, f) {
		t.Fatal("out-of-order reassembly failed")
	}
}

// TestReassemble_DualPathNoDoubleDelivery: the same frame arriving twice (both
// UDP paths) must be delivered exactly once — the second path's copies must not
// re-complete the frame after the first path already delivered it.
func TestReassemble_DualPathNoDoubleDelivery(t *testing.T) {
	f := makeFrame(3000)
	pieces := Split(f, 1400) // 3 pieces
	r := NewReassembler()

	deliveries := 0
	feed := func() {
		for i, p := range pieces {
			if out := r.Add(55, uint8(i), uint8(len(pieces)), p); out != nil {
				deliveries++
				if !bytes.Equal(out, f) {
					t.Fatal("delivered frame mismatch")
				}
			}
		}
	}
	feed() // primary path
	feed() // secondary path: identical pieces, must NOT re-deliver

	if deliveries != 1 {
		t.Fatalf("frame delivered %d times, want exactly 1", deliveries)
	}
}

func TestReassemble_SinglePiece(t *testing.T) {
	r := NewReassembler()
	f := makeFrame(500)
	out := r.Add(1, 0, 1, f)
	if !bytes.Equal(out, f) {
		t.Fatal("count=1 must deliver immediately")
	}
}

func TestReassemble_InvalidIdx(t *testing.T) {
	r := NewReassembler()
	if r.Add(1, 3, 3, makeFrame(10)) != nil {
		t.Fatal("idx >= count must be rejected")
	}
	if r.Add(1, 0, 0, makeFrame(10)) != nil {
		t.Fatal("count=0 must be rejected")
	}
}

func TestReassemble_TTLEviction(t *testing.T) {
	r := NewReassembler()
	base := time.Unix(1000, 0)
	r.now = func() time.Time { return base }
	// Start an incomplete frame (piece 0 of 2).
	if r.Add(9, 0, 2, makeFrame(100)) != nil {
		t.Fatal("incomplete frame should not deliver")
	}
	// Advance past the TTL; a new unrelated fragID triggers eviction of the stale one.
	base = base.Add(reassemblyTTL + time.Second)
	r.Add(10, 0, 2, makeFrame(100))
	r.mu.Lock()
	_, stale := r.pending[9]
	r.mu.Unlock()
	if stale {
		t.Fatal("stale partial should have been evicted after TTL")
	}
}
