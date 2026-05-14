package hub

import (
	"context"
	"sync"
	"testing"
	"time"
)

// makeFrame builds a minimal 14-byte Ethernet frame (dst + src MACs).
func makeFrame(dst, src [6]byte) []byte {
	frame := make([]byte, 14)
	copy(frame[0:6], dst[:])
	copy(frame[6:12], src[:])
	// EtherType = 0x0800 (IPv4)
	frame[12] = 0x08
	frame[13] = 0x00
	return frame
}

// newCaptureClient creates a Client that captures frames sent to it.
// Returns the client and a function to drain all captured frames.
func newCaptureClient(sessionID uint32) (*Client, func() [][]byte) {
	var mu sync.Mutex
	var captured [][]byte
	c := &Client{
		SessionID: sessionID,
		Login:     "test",
		Send: func(frame []byte) error {
			cp := make([]byte, len(frame))
			copy(cp, frame)
			mu.Lock()
			captured = append(captured, cp)
			mu.Unlock()
			return nil
		},
	}
	drain := func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]byte, len(captured))
		copy(out, captured)
		captured = nil
		return out
	}
	return c, drain
}

// TestHub_BroadcastOnUnknownUnicast: client 1 sends a frame with unknown dst MAC;
// clients 2 and 3 should receive it, client 1 should NOT.
func TestHub_BroadcastOnUnknownUnicast(t *testing.T) {
	h := New(1, "test")
	c1, drain1 := newCaptureClient(1)
	c2, drain2 := newCaptureClient(2)
	c3, drain3 := newCaptureClient(3)
	h.Join(c1)
	h.Join(c2)
	h.Join(c3)

	srcMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	dstMAC := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66} // unknown

	frame := makeFrame(dstMAC, srcMAC)
	h.Forward(c1.SessionID, frame)

	if len(drain1()) != 0 {
		t.Error("sender (client 1) should NOT receive its own frame")
	}
	if len(drain2()) != 1 {
		t.Error("client 2 should receive the flooded frame")
	}
	if len(drain3()) != 1 {
		t.Error("client 3 should receive the flooded frame")
	}
}

// TestHub_MACLearningAndUnicast: after MAC learning, frames are unicast to the right client.
func TestHub_MACLearningAndUnicast(t *testing.T) {
	h := New(1, "test")
	c1, drain1 := newCaptureClient(1)
	c2, drain2 := newCaptureClient(2)
	c3, drain3 := newCaptureClient(3)
	h.Join(c1)
	h.Join(c2)
	h.Join(c3)

	macA := [6]byte{0xAA, 0x00, 0x00, 0x00, 0x00, 0x01}
	macB := [6]byte{0xBB, 0x00, 0x00, 0x00, 0x00, 0x02}

	// Client 1 sends frame with src=macA, dst=macB (unknown → broadcast)
	h.Forward(c1.SessionID, makeFrame(macB, macA))
	drain1() // discard
	got2 := drain2()
	got3 := drain3()
	if len(got2) != 1 || len(got3) != 1 {
		t.Fatalf("expected both client 2 and 3 to receive broadcast; got %d and %d", len(got2), len(got3))
	}

	// Client 2 sends frame src=macB, dst=macA — macA is now learned on session 1
	h.Forward(c2.SessionID, makeFrame(macA, macB))
	got1 := drain1()
	drain2() // should be empty — sender
	drain3()
	if len(got1) != 1 {
		t.Errorf("expected unicast to client 1 (learned MAC_A), got %d frames", len(got1))
	}
}

// TestHub_BroadcastToAllExceptSource: broadcast frames go to all clients except sender.
func TestHub_BroadcastToAllExceptSource(t *testing.T) {
	h := New(1, "test")
	c1, drain1 := newCaptureClient(1)
	c2, drain2 := newCaptureClient(2)
	c3, drain3 := newCaptureClient(3)
	c4, drain4 := newCaptureClient(4)
	h.Join(c1)
	h.Join(c2)
	h.Join(c3)
	h.Join(c4)

	broadcast := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	srcMAC := [6]byte{0xAA, 0x00, 0x00, 0x00, 0x00, 0x01}

	h.Forward(c1.SessionID, makeFrame(broadcast, srcMAC))

	if len(drain1()) != 0 {
		t.Error("sender should not receive its own broadcast")
	}
	if len(drain2()) != 1 {
		t.Error("client 2 should receive broadcast")
	}
	if len(drain3()) != 1 {
		t.Error("client 3 should receive broadcast")
	}
	if len(drain4()) != 1 {
		t.Error("client 4 should receive broadcast")
	}
}

// TestHub_Leave: removed client no longer receives frames.
func TestHub_Leave(t *testing.T) {
	h := New(1, "test")
	c1, drain1 := newCaptureClient(1)
	c2, drain2 := newCaptureClient(2)
	c3, drain3 := newCaptureClient(3)
	h.Join(c1)
	h.Join(c2)
	h.Join(c3)

	// Remove client 3
	h.Leave(c3.SessionID)

	srcMAC := [6]byte{0xAA, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66} // unknown → flood
	h.Forward(c1.SessionID, makeFrame(dstMAC, srcMAC))

	drain1() // sender — always empty
	if len(drain2()) != 1 {
		t.Error("client 2 (still joined) should receive the frame")
	}
	if len(drain3()) != 0 {
		t.Error("client 3 (left) should NOT receive the frame")
	}
}

// TestHub_ShortFrame: a frame shorter than 12 bytes must not panic.
func TestHub_ShortFrame(t *testing.T) {
	h := New(1, "test")
	c1, _ := newCaptureClient(1)
	h.Join(c1)

	// Should return silently without panic
	h.Forward(c1.SessionID, []byte{0x01, 0x02, 0x03})
	h.Forward(c1.SessionID, nil)
	h.Forward(c1.SessionID, []byte{})
	h.Forward(c1.SessionID, make([]byte, 11))
}

// TestHub_ConcurrentForward: concurrent senders must not race or deadlock.
func TestHub_ConcurrentForward(t *testing.T) {
	const numClients = 10
	const framesPerClient = 100

	h := New(1, "test")
	clients := make([]*Client, numClients)
	for i := 0; i < numClients; i++ {
		c, _ := newCaptureClient(uint32(i + 1))
		clients[i] = c
		h.Join(c)
	}

	var wg sync.WaitGroup
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			src := [6]byte{0xAA, 0x00, 0x00, 0x00, 0x00, byte(idx + 1)}
			dst := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} // broadcast
			frame := makeFrame(dst, src)
			for j := 0; j < framesPerClient; j++ {
				h.Forward(clients[idx].SessionID, frame)
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Forward timed out (possible deadlock)")
	}
}

// TestManager_AddGet: Manager correctly stores and retrieves hubs.
func TestManager_AddGet(t *testing.T) {
	m := NewManager()

	h1 := New(1, "alpha")
	h2 := New(2, "beta")
	h3 := New(3, "gamma")
	m.Add(h1)
	m.Add(h2)
	m.Add(h3)

	got1, ok := m.Get(1)
	if !ok || got1.Name() != "alpha" {
		t.Errorf("Get(1): expected alpha hub, got ok=%v name=%q", ok, got1.Name())
	}
	got2, ok := m.Get(2)
	if !ok || got2.Name() != "beta" {
		t.Errorf("Get(2): expected beta hub, got ok=%v name=%q", ok, got2.Name())
	}
	_, ok = m.Get(99)
	if ok {
		t.Error("Get(99): expected false for non-existent hub")
	}

	list := m.List()
	if len(list) != 3 {
		t.Errorf("List(): expected 3 hubs, got %d", len(list))
	}
}

// TestHub_MACPurge: inject an already-expired MAC entry and verify purgeMACTable removes it.
func TestHub_MACPurge(t *testing.T) {
	h := New(1, "test")

	mac := [6]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}

	// Inject an expired entry directly into the mac table
	h.mu.Lock()
	h.macTable[mac] = macEntry{
		sessionID: 42,
		expires:   time.Now().Add(-1 * time.Second), // already expired
	}
	h.mu.Unlock()

	// Verify it's present before purge
	h.mu.RLock()
	_, present := h.macTable[mac]
	h.mu.RUnlock()
	if !present {
		t.Fatal("test setup failed: expired MAC entry not found in table")
	}

	h.purgeMACTable()

	h.mu.RLock()
	_, present = h.macTable[mac]
	h.mu.RUnlock()
	if present {
		t.Error("purgeMACTable should have removed the expired entry")
	}
}

// TestHub_MACPurge_KeepsValid: purgeMACTable must NOT remove fresh entries.
func TestHub_MACPurge_KeepsValid(t *testing.T) {
	h := New(1, "test")

	mac := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	h.mu.Lock()
	h.macTable[mac] = macEntry{
		sessionID: 1,
		expires:   time.Now().Add(1 * time.Minute), // not expired
	}
	h.mu.Unlock()

	h.purgeMACTable()

	h.mu.RLock()
	_, present := h.macTable[mac]
	h.mu.RUnlock()
	if !present {
		t.Error("purgeMACTable removed a valid (non-expired) entry")
	}
}

// TestHub_StartMACPurge_ContextCancel: StartMACPurge goroutine should stop when ctx is cancelled.
func TestHub_StartMACPurge_ContextCancel(t *testing.T) {
	h := New(1, "test")
	ctx, cancel := context.WithCancel(context.Background())
	h.StartMACPurge(ctx)
	// Just ensure cancellation doesn't hang
	cancel()
	// Give the goroutine a moment to exit
	time.Sleep(10 * time.Millisecond)
}

// TestHub_ClientCount: ClientCount reflects joined and left clients.
func TestHub_ClientCount(t *testing.T) {
	h := New(1, "test")
	if h.ClientCount() != 0 {
		t.Errorf("empty hub should have 0 clients, got %d", h.ClientCount())
	}
	c1, _ := newCaptureClient(1)
	c2, _ := newCaptureClient(2)
	h.Join(c1)
	h.Join(c2)
	if h.ClientCount() != 2 {
		t.Errorf("expected 2 clients, got %d", h.ClientCount())
	}
	h.Leave(c1.SessionID)
	if h.ClientCount() != 1 {
		t.Errorf("expected 1 client after leave, got %d", h.ClientCount())
	}
}

// TestHub_UnicastNoLeakToThird: after MAC is learned, unicast does NOT go to other clients.
func TestHub_UnicastNoLeakToThird(t *testing.T) {
	h := New(1, "test")
	c1, drain1 := newCaptureClient(1)
	c2, drain2 := newCaptureClient(2)
	c3, drain3 := newCaptureClient(3)
	h.Join(c1)
	h.Join(c2)
	h.Join(c3)

	macA := [6]byte{0xAA, 0x00, 0x00, 0x00, 0x00, 0x01}
	macB := [6]byte{0xBB, 0x00, 0x00, 0x00, 0x00, 0x02}

	// Learn macA on session c1
	h.Forward(c1.SessionID, makeFrame(macB, macA))
	drain1()
	drain2()
	drain3()

	// Learn macB on session c2
	h.Forward(c2.SessionID, makeFrame(macA, macB))
	drain1()
	drain2()
	drain3()

	// Now unicast macA→c1, should NOT reach c3
	h.Forward(c2.SessionID, makeFrame(macA, macB))
	got1 := drain1()
	drain2()
	got3 := drain3()

	if len(got1) != 1 {
		t.Errorf("unicast target should get the frame, got %d", len(got1))
	}
	if len(got3) != 0 {
		t.Errorf("non-target client 3 should NOT get the unicast frame, got %d", len(got3))
	}
}
