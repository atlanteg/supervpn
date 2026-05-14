package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey_Symmetric(t *testing.T) {
	a, err := DeriveKey("token", "test-net", "host-a", "host-b")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKey("token", "test-net", "host-b", "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("key(A,B) != key(B,A)")
	}
}

func TestDeriveKey_DifferentNetworks(t *testing.T) {
	keyA, _ := DeriveKey("token", "net-alpha", "host-a", "host-b")
	keyB, _ := DeriveKey("token", "net-beta", "host-a", "host-b")
	if bytes.Equal(keyA, keyB) {
		t.Fatal("different network names must produce different keys")
	}
}

func TestDeriveKey_DifferentPairs(t *testing.T) {
	ab, _ := DeriveKey("token", "test-net", "host-a", "host-b")
	ac, _ := DeriveKey("token", "test-net", "host-a", "host-c")
	if bytes.Equal(ab, ac) {
		t.Fatal("different peer pairs must produce different keys")
	}
}

func TestDeriveKey_EmptyToken(t *testing.T) {
	_, err := DeriveKey("", "test-net", "host-a", "host-b")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestCipher_RoundTrip(t *testing.T) {
	key, _ := DeriveKey("secret", "test-net", "host-a", "host-b")
	c, err := NewCipher(key, 1)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("hello overlay world")
	pkt, err := c.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}

	var rw ReplayWindow
	got, err := c.Open(pkt, &rw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q, want %q", got, plain)
	}
}

func TestCipher_TamperedPacket(t *testing.T) {
	key, _ := DeriveKey("secret", "test-net", "host-a", "host-b")
	c, _ := NewCipher(key, 1)

	pkt, _ := c.Seal([]byte("data"))
	pkt[len(pkt)-1] ^= 0xff // flip last byte of GCM tag

	var rw ReplayWindow
	_, err := c.Open(pkt, &rw)
	if err == nil {
		t.Fatal("expected authentication failure on tampered packet")
	}
}

func TestCipher_PacketTooShort(t *testing.T) {
	key, _ := DeriveKey("secret", "test-net", "host-a", "host-b")
	c, _ := NewCipher(key, 1)

	var rw ReplayWindow
	_, err := c.Open([]byte("short"), &rw)
	if err == nil {
		t.Fatal("expected error for short packet")
	}
}

func TestReplayWindow_Accept(t *testing.T) {
	var rw ReplayWindow
	for i := uint64(1); i <= 10; i++ {
		if !rw.Check(i) {
			t.Fatalf("counter %d should be accepted", i)
		}
	}
}

func TestReplayWindow_RejectReplay(t *testing.T) {
	var rw ReplayWindow
	rw.Check(5)
	if rw.Check(5) {
		t.Fatal("duplicate counter must be rejected")
	}
}

func TestReplayWindow_RejectZero(t *testing.T) {
	var rw ReplayWindow
	if rw.Check(0) {
		t.Fatal("counter 0 must be rejected")
	}
}

func TestReplayWindow_RejectTooOld(t *testing.T) {
	var rw ReplayWindow
	rw.Check(600)
	// counter 87 is 513 positions behind maxSeen=600, outside the 512-slot window
	if rw.Check(87) {
		t.Fatal("counter outside window must be rejected")
	}
}

func TestReplayWindow_AcceptLargeReorder(t *testing.T) {
	var rw ReplayWindow
	rw.Check(512)
	// counter 1 is 511 positions behind maxSeen=512, inside the 512-slot window
	if !rw.Check(1) {
		t.Fatal("counter 511 positions behind maxSeen must be accepted")
	}
	// duplicate must be rejected
	if rw.Check(1) {
		t.Fatal("duplicate counter must be rejected")
	}
}

func TestReplayWindow_AcceptReorder(t *testing.T) {
	var rw ReplayWindow
	rw.Check(10)
	// counter 5 is 5 behind maxSeen=10, still inside the window
	if !rw.Check(5) {
		t.Fatal("out-of-order counter within window must be accepted")
	}
	// but not twice
	if rw.Check(5) {
		t.Fatal("duplicate out-of-order counter must be rejected")
	}
}
