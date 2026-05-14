package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// startLocalListener starts a local TCP listener and returns it.
// Callers are responsible for closing it.
func startLocalListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	return ln
}

// dialAndAccept creates a client TCPTransport connected to ln and
// returns (client, server) TCPTransport pair. The listener is NOT closed by this helper.
func dialAndAccept(t *testing.T, ln net.Listener) (client, server *TCPTransport) {
	t.Helper()
	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- accepted{conn, err}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	result := <-ch
	if result.err != nil {
		t.Fatalf("ln.Accept: %v", result.err)
	}
	return WrapTCP(clientConn), WrapTCP(result.conn)
}

// TestTCPTransport_SendRecv: basic single-frame send and receive.
func TestTCPTransport_SendRecv(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()

	want := []byte("hello supervpn")
	if err := client.Send(Frame{Data: want}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := server.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got.Data, want) {
		t.Errorf("Recv: got %v, want %v", got.Data, want)
	}
}

// TestTCPTransport_MultipleFrames: send 10 frames of varying sizes and receive them all.
func TestTCPTransport_MultipleFrames(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()

	sizes := []int{1, 10, 100, 500, 1000, 1400, 14, 42, 255, 1024}
	var sent [][]byte
	for i, sz := range sizes {
		data := make([]byte, sz)
		for j := range data {
			data[j] = byte(i*7 + j)
		}
		sent = append(sent, data)
		if err := client.Send(Frame{Data: data}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := range sent {
		got, err := server.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv[%d]: %v", i, err)
		}
		if !bytes.Equal(got.Data, sent[i]) {
			t.Errorf("Recv[%d]: data mismatch (len got=%d want=%d)", i, len(got.Data), len(sent[i]))
		}
	}
}

// TestTCPTransport_MaxSize: a frame of exactly 65535 bytes must succeed.
func TestTCPTransport_MaxSize(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()

	data := make([]byte, 65535)
	for i := range data {
		data[i] = byte(i)
	}

	if err := client.Send(Frame{Data: data}); err != nil {
		t.Fatalf("Send max-size frame: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := server.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv max-size frame: %v", err)
	}
	if len(got.Data) != 65535 {
		t.Errorf("expected 65535 bytes, got %d", len(got.Data))
	}
	if !bytes.Equal(got.Data, data) {
		t.Error("max-size frame data mismatch")
	}
}

// TestTCPTransport_EmptyFrame: a zero-length frame round-trips without error.
func TestTCPTransport_EmptyFrame(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()

	if err := client.Send(Frame{Data: nil}); err != nil {
		t.Fatalf("Send empty frame: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := server.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv empty frame: %v", err)
	}
	if len(got.Data) != 0 {
		t.Errorf("expected empty frame, got %d bytes", len(got.Data))
	}
}

// TestTCPTransport_Mode: Mode() must return "tcp".
func TestTCPTransport_Mode(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()

	if client.Mode() != "tcp" {
		t.Errorf("client.Mode(): got %q, want %q", client.Mode(), "tcp")
	}
	if server.Mode() != "tcp" {
		t.Errorf("server.Mode(): got %q, want %q", server.Mode(), "tcp")
	}
}

// TestTCPTransport_Close: after Close, Recv returns an error.
func TestTCPTransport_Close(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer client.Close()

	// Close the server side
	server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := server.Recv(ctx)
	if err == nil {
		t.Error("Recv after Close should return an error")
	}
}

// TestTCPTransport_PeerClose: when the peer closes the connection, Recv returns an error.
func TestTCPTransport_PeerClose(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer server.Close()

	// Close the client side; server Recv should get EOF or similar
	client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := server.Recv(ctx)
	if err == nil {
		t.Error("server Recv should error after peer closes the connection")
	}
}

// TestDialTCP_InvalidAddr: DialTCP to a non-listening address returns an error.
func TestDialTCP_InvalidAddr(t *testing.T) {
	_, err := DialTCP("127.0.0.1:1") // port 1 is very unlikely to be open
	if err == nil {
		t.Error("DialTCP to non-listening addr should return error")
	}
}

// TestTCPTransport_ContextCancel: cancelling context while blocked in Recv unblocks it.
func TestTCPTransport_ContextCancel(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())

	recvErr := make(chan error, 1)
	go func() {
		_, err := server.Recv(ctx)
		recvErr <- err
	}()

	// Give the goroutine time to block in Recv
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-recvErr:
		if err == nil {
			t.Error("Recv should return an error after context cancel")
		}
		// Acceptable: context.Canceled or io.EOF/io.ErrClosedPipe (connection closed by ctx goroutine)
		if err != context.Canceled && err != io.EOF {
			// Any non-nil error is fine — the connection was closed
			_ = err
		}
	case <-time.After(2 * time.Second):
		t.Error("Recv did not unblock after context cancel")
	}
}

// TestTCPTransport_BidirectionalCommunication: both sides can send and receive.
func TestTCPTransport_BidirectionalCommunication(t *testing.T) {
	ln := startLocalListener(t)
	defer ln.Close()

	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	clientMsg := []byte("from client")
	serverMsg := []byte("from server")

	// Client → Server
	if err := client.Send(Frame{Data: clientMsg}); err != nil {
		t.Fatalf("client Send: %v", err)
	}
	got, err := server.Recv(ctx)
	if err != nil {
		t.Fatalf("server Recv: %v", err)
	}
	if !bytes.Equal(got.Data, clientMsg) {
		t.Errorf("server Recv: got %v, want %v", got.Data, clientMsg)
	}

	// Server → Client
	if err := server.Send(Frame{Data: serverMsg}); err != nil {
		t.Fatalf("server Send: %v", err)
	}
	got, err = client.Recv(ctx)
	if err != nil {
		t.Fatalf("client Recv: %v", err)
	}
	if !bytes.Equal(got.Data, serverMsg) {
		t.Errorf("client Recv: got %v, want %v", got.Data, serverMsg)
	}
}
