package bridge

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// mockFramer implements Framer for tests.
// ReadFrame returns frames from the frames slice one by one, then returns readErr.
// WriteFrame appends frames to written.
type mockFramer struct {
	mu      sync.Mutex
	frames  [][]byte // frames to return from ReadFrame
	pos     int
	readErr error    // error to return after all frames are consumed
	written [][]byte // frames captured by WriteFrame
	closed  bool
}

func (m *mockFramer) ReadFrame(ctx context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pos < len(m.frames) {
		f := m.frames[m.pos]
		m.pos++
		return f, nil
	}
	if m.readErr != nil {
		return nil, m.readErr
	}
	// Block until context is cancelled if no error set
	m.mu.Unlock()
	<-ctx.Done()
	m.mu.Lock()
	return nil, ctx.Err()
}

func (m *mockFramer) WriteFrame(frame []byte) error {
	cp := make([]byte, len(frame))
	copy(cp, frame)
	m.mu.Lock()
	m.written = append(m.written, cp)
	m.mu.Unlock()
	return nil
}

func (m *mockFramer) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

func (m *mockFramer) getWritten() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.written))
	copy(out, m.written)
	return out
}

// TestDetectLinkLocal_ReturnsSlice: verify the function doesn't panic and returns a slice.
func TestDetectLinkLocal_ReturnsSlice(t *testing.T) {
	ifaces, err := DetectLinkLocal()
	if err != nil {
		t.Errorf("DetectLinkLocal returned error: %v", err)
	}
	// ifaces may be empty (host may not have link-local addresses), just must not panic.
	_ = ifaces
}

// TestBridge_RunUpstream: mock Framer that returns 3 frames then context.Canceled;
// all 3 frames must reach the send function.
func TestBridge_RunUpstream(t *testing.T) {
	frames := [][]byte{
		{0x01, 0x02, 0x03},
		{0xAA, 0xBB},
		{0x11, 0x22, 0x33, 0x44},
	}
	framer := &mockFramer{
		frames:  frames,
		readErr: context.Canceled,
	}

	var mu sync.Mutex
	var received [][]byte
	sendFn := func(frame []byte) error {
		cp := make([]byte, len(frame))
		copy(cp, frame)
		mu.Lock()
		received = append(received, cp)
		mu.Unlock()
		return nil
	}

	b := New(Interface{Name: "test"}, framer, sendFn)
	ctx := context.Background()
	err := b.RunUpstream(ctx)
	if err == nil {
		t.Error("RunUpstream should return an error when Framer returns one")
	}

	mu.Lock()
	got := len(received)
	mu.Unlock()

	if got != len(frames) {
		t.Errorf("expected %d frames to be sent, got %d", len(frames), got)
	}
	mu.Lock()
	for i, f := range received {
		if string(f) != string(frames[i]) {
			t.Errorf("frame %d mismatch: got %v, want %v", i, f, frames[i])
		}
	}
	mu.Unlock()
}

// TestBridge_RunUpstream_SendError: if send returns an error, RunUpstream stops.
func TestBridge_RunUpstream_SendError(t *testing.T) {
	framer := &mockFramer{
		frames: [][]byte{{0x01}, {0x02}, {0x03}},
	}
	sendErr := errors.New("network broken")
	calls := 0
	sendFn := func(frame []byte) error {
		calls++
		return sendErr
	}

	b := New(Interface{Name: "test"}, framer, sendFn)
	err := b.RunUpstream(context.Background())
	if err == nil {
		t.Error("RunUpstream should propagate send error")
	}
	if calls != 1 {
		t.Errorf("expected send to be called exactly once before stopping, got %d", calls)
	}
}

// TestBridge_RunDownstream: send 5 frames via the downstream channel; all must be written to Framer.
func TestBridge_RunDownstream(t *testing.T) {
	framer := &mockFramer{}
	b := New(Interface{Name: "test"}, framer, func([]byte) error { return nil })

	ch := make(chan []byte, 5)
	frames := [][]byte{
		{0x01},
		{0x02, 0x03},
		{0x04, 0x05, 0x06},
		{0x07},
		{0x08, 0x09},
	}
	for _, f := range frames {
		ch <- f
	}
	close(ch)

	ctx := context.Background()
	err := b.RunDownstream(ctx, ch)
	if err != io.EOF {
		t.Errorf("RunDownstream: expected io.EOF on closed channel, got %v", err)
	}

	written := framer.getWritten()
	if len(written) != len(frames) {
		t.Errorf("expected %d frames written, got %d", len(frames), len(written))
	}
	for i, want := range frames {
		if string(written[i]) != string(want) {
			t.Errorf("frame %d mismatch: got %v, want %v", i, written[i], want)
		}
	}
}

// TestBridge_RunDownstream_ContextCancel: RunDownstream returns ctx.Err() when context is cancelled.
func TestBridge_RunDownstream_ContextCancel(t *testing.T) {
	framer := &mockFramer{}
	b := New(Interface{Name: "test"}, framer, func([]byte) error { return nil })

	ch := make(chan []byte) // never written to
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- b.RunDownstream(ctx, ch)
	}()

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("RunDownstream: expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("RunDownstream did not return after context cancel")
	}
}

// TestBridge_Inject: Inject calls WriteFrame on the underlying Framer.
func TestBridge_Inject(t *testing.T) {
	framer := &mockFramer{}
	b := New(Interface{Name: "test"}, framer, func([]byte) error { return nil })

	frame := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := b.Inject(frame); err != nil {
		t.Errorf("Inject returned error: %v", err)
	}

	written := framer.getWritten()
	if len(written) != 1 {
		t.Fatalf("expected 1 frame written via Inject, got %d", len(written))
	}
	if string(written[0]) != string(frame) {
		t.Errorf("Inject: wrong frame data: got %v, want %v", written[0], frame)
	}
}

// TestBridge_RunDownstream_Empty: immediately-closed channel returns io.EOF right away.
func TestBridge_RunDownstream_Empty(t *testing.T) {
	framer := &mockFramer{}
	b := New(Interface{Name: "test"}, framer, func([]byte) error { return nil })

	ch := make(chan []byte)
	close(ch)

	err := b.RunDownstream(context.Background(), ch)
	if err != io.EOF {
		t.Errorf("expected io.EOF for immediately closed channel, got %v", err)
	}
	if len(framer.getWritten()) != 0 {
		t.Error("expected no frames written for empty channel")
	}
}
