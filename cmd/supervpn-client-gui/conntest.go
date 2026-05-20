package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
)

// ServerTestResult holds UDP and TCP reachability for one server.
type ServerTestResult struct {
	Name string
	Addr string
	UDP  string // e.g. "✓ OK", "✗ timeout", "✗ error: ..."
	TCP  string
}

// TestAllServers runs UDP and TCP connectivity checks for every predefined
// server and streams results through the returned channel.  The channel is
// closed when all tests finish.  Each server is tested concurrently.
func TestAllServers() <-chan ServerTestResult {
	ch := make(chan ServerTestResult, len(predefinedServers))
	go func() {
		done := make(chan struct{}, len(predefinedServers))
		for _, s := range predefinedServers {
			s := s
			go func() {
				ch <- ServerTestResult{
					Name: s.name,
					Addr: s.addr,
					UDP:  testUDP(s.addr),
					TCP:  testTCP(s.addr),
				}
				done <- struct{}{}
			}()
		}
		for range predefinedServers {
			<-done
		}
		close(ch)
	}()
	return ch
}

// testUDP sends a FrameListHubs request and waits up to 3 s for any response.
// Uses our own protocol so the test is meaningful even behind NAT.
func testUDP(addr string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tr, err := transport.DialUDP(addr)
	if err != nil {
		return fmt.Sprintf("✗ dial: %v", err)
	}
	defer tr.Close()

	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameListHubs}.Marshal(hdr)
	if err := tr.Send(transport.Frame{Data: hdr}); err != nil {
		return fmt.Sprintf("✗ send: %v", err)
	}

	_, err = tr.Recv(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return "✗ timeout"
		}
		return fmt.Sprintf("✗ %v", err)
	}
	return "✓ OK"
}

// testTCP dials the server's TCP port (443) with a 3 s timeout.
func testTCP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "✗ bad addr"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 3*time.Second)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "✗ timeout"
		}
		return fmt.Sprintf("✗ %v", err)
	}
	conn.Close()
	return "✓ OK"
}
