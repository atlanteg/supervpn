package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"
)

// startTLSServer starts a TLS listener on a random port and returns the address.
// It accepts exactly one connection and runs fn(serverConn) in a goroutine.
// The listener is closed after the first accept.
func startTLSServer(t *testing.T, cfg *tls.Config, fn func(*TLSTransport)) net.Listener {
	t.Helper()
	ln, err := ListenTLS("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("ListenTLS: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		fn(AcceptTLS(conn))
	}()
	return ln
}

// TestTLSTransport_SendRecv tests a full TLS round-trip: client→server and server→client.
func TestTLSTransport_SendRecv(t *testing.T) {
	cfg, err := NewServerTLSConfig("", "")
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	clientMsg := []byte("hello from client")
	serverMsg := []byte("hello from server")

	var wg sync.WaitGroup
	wg.Add(1)

	ln := startTLSServer(t, cfg, func(srv *TLSTransport) {
		defer wg.Done()
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// receive from client
		f, err := srv.Recv(ctx)
		if err != nil {
			t.Errorf("server Recv: %v", err)
			return
		}
		if !bytes.Equal(f.Data, clientMsg) {
			t.Errorf("server got %q, want %q", f.Data, clientMsg)
		}

		// send to client
		if err := srv.Send(Frame{Data: serverMsg}); err != nil {
			t.Errorf("server Send: %v", err)
		}
	})
	defer ln.Close()

	cli, err := DialTLS(ln.Addr().String(), "test.local")
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer cli.Close()

	// send to server
	if err := cli.Send(Frame{Data: clientMsg}); err != nil {
		t.Fatalf("client Send: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// receive from server
	f, err := cli.Recv(ctx)
	if err != nil {
		t.Fatalf("client Recv: %v", err)
	}
	if !bytes.Equal(f.Data, serverMsg) {
		t.Errorf("client got %q, want %q", f.Data, serverMsg)
	}

	wg.Wait()
}

// TestTLSTransport_Mode verifies that Mode() returns "tls".
func TestTLSTransport_Mode(t *testing.T) {
	cfg, err := NewServerTLSConfig("", "")
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	ln := startTLSServer(t, cfg, func(srv *TLSTransport) {
		defer wg.Done()
		defer srv.Close()
		// Echo one frame so the handshake is fully established.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		f, _ := srv.Recv(ctx)
		_ = srv.Send(f)
	})
	defer ln.Close()

	cli, err := DialTLS(ln.Addr().String(), "test.local")
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer cli.Close()

	// Send a ping so the server goroutine exits cleanly.
	_ = cli.Send(Frame{Data: []byte("ping")})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = cli.Recv(ctx)

	if got := cli.Mode(); got != "tls" {
		t.Errorf("Mode() = %q, want %q", got, "tls")
	}
	wg.Wait()
}

// TestTLSTransport_MultipleFrames sends 20 frames of varying sizes through TLS.
func TestTLSTransport_MultipleFrames(t *testing.T) {
	const numFrames = 20

	cfg, err := NewServerTLSConfig("", "")
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	// Build frames with varying sizes (1..numFrames * 100 bytes).
	frames := make([][]byte, numFrames)
	for i := range frames {
		frames[i] = bytes.Repeat([]byte{byte(i + 1)}, (i+1)*100)
	}

	received := make([][]byte, 0, numFrames)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)

	ln := startTLSServer(t, cfg, func(srv *TLSTransport) {
		defer wg.Done()
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for i := 0; i < numFrames; i++ {
			f, err := srv.Recv(ctx)
			if err != nil {
				t.Errorf("server Recv[%d]: %v", i, err)
				return
			}
			mu.Lock()
			received = append(received, f.Data)
			mu.Unlock()
		}
	})
	defer ln.Close()

	cli, err := DialTLS(ln.Addr().String(), "test.local")
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer cli.Close()

	for i, data := range frames {
		if err := cli.Send(Frame{Data: data}); err != nil {
			t.Fatalf("client Send[%d]: %v", i, err)
		}
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(received) != numFrames {
		t.Fatalf("received %d frames, want %d", len(received), numFrames)
	}
	for i, data := range received {
		if !bytes.Equal(data, frames[i]) {
			t.Errorf("frame[%d]: got len=%d, want len=%d", i, len(data), len(frames[i]))
		}
	}
}

// TestTLSTransport_SelfSignedCert verifies generateSelfSignedCert produces a valid certificate.
func TestTLSTransport_SelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("cert has no DER blocks")
	}
	// Parse the leaf to confirm it's well-formed.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", leaf.PublicKeyAlgorithm)
	}
	if leaf.NotAfter.Before(time.Now().Add(9 * 365 * 24 * time.Hour)) {
		t.Errorf("cert expires too soon: %v", leaf.NotAfter)
	}
}

// TestTLSTransport_InvalidAddr verifies that DialTLS to an unreachable address returns an error.
func TestTLSTransport_InvalidAddr(t *testing.T) {
	// Port 1 is unlikely to be open; expect immediate connection refusal.
	_, err := DialTLS("127.0.0.1:1", "test.local")
	if err == nil {
		t.Fatal("expected error dialing invalid addr, got nil")
	}
}

// TestNewServerTLSConfig_Generated verifies the generated config enforces TLS 1.3.
func TestNewServerTLSConfig_Generated(t *testing.T) {
	cfg, err := NewServerTLSConfig("", "")
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = 0x%04x, want 0x%04x (TLS 1.3)", cfg.MinVersion, tls.VersionTLS13)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("MaxVersion = 0x%04x, want 0x%04x (TLS 1.3)", cfg.MaxVersion, tls.VersionTLS13)
	}
	if len(cfg.Certificates) == 0 {
		t.Fatal("config has no certificates")
	}
}

// TestTLSTransport_AcceptTLS_PlainConn verifies AcceptTLS falls back gracefully
// when given a plain (non-TLS) net.Conn.
func TestTLSTransport_AcceptTLS_PlainConn(t *testing.T) {
	// Use a pair of net.Pipe connections as plain net.Conn.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tr := AcceptTLS(c1)
	if tr == nil {
		t.Fatal("AcceptTLS returned nil")
	}
	if tr.TCPTransport == nil {
		t.Fatal("TCPTransport is nil in fallback path")
	}
	// conn field should be nil in the plain fallback path.
	if tr.conn != nil {
		t.Error("expected conn to be nil for plain conn fallback")
	}
	// Mode should still return "tls" via the embedded type.
	if got := tr.Mode(); got != "tls" {
		t.Errorf("Mode() = %q, want %q", got, "tls")
	}
}

// Compile-time check: TLSTransport implements Transport.
var _ Transport = (*TLSTransport)(nil)

// TestTLSTransport_SNI verifies that the SNI field is actually sent by capturing
// the server-side connection state after handshake.
func TestTLSTransport_SNI(t *testing.T) {
	cfg, err := NewServerTLSConfig("", "")
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	sniSeen := make(chan string, 1)

	ln := startTLSServer(t, cfg, func(srv *TLSTransport) {
		defer srv.Close()
		if srv.conn != nil {
			// Explicitly complete the TLS handshake so ServerName is populated.
			_ = srv.conn.Handshake()
			state := srv.conn.ConnectionState()
			sniSeen <- state.ServerName
		} else {
			sniSeen <- ""
		}
		// Echo one frame to let the client finish its send/recv cycle cleanly.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		f, _ := srv.Recv(ctx)
		_ = srv.Send(f)
	})
	defer ln.Close()

	wantSNI := "microsoft.com"
	cli, err := DialTLS(ln.Addr().String(), wantSNI)
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer cli.Close()

	select {
	case got := <-sniSeen:
		if got != wantSNI {
			t.Errorf("server saw SNI %q, want %q", got, wantSNI)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SNI")
	}

	// Trigger the server's echo so it exits cleanly.
	_ = cli.Send(Frame{Data: []byte("bye")})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = cli.Recv(ctx)
}
