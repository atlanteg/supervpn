package main

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
)

// Port layout probed by the test tab:
//
//	UDP  — primary UDP (the server's configured port)
//	UDP2 — secondary UDP (port+1, dual-path)
//	TCP  — plain TLS/TCP fallback (:8443)
//	TCP2 — secondary TLS/TCP (:8444, dual-path)
//	Reality — stealth VLESS+Reality front (:443)
const (
	realityPort = "443"
	tlsPort     = "8443"
	tls2Port    = "8444"
)

// ServerTestResult holds reachability for every transport/port of one server.
type ServerTestResult struct {
	Name    string
	Addr    string
	UDP     string // primary UDP
	UDP2    string // secondary UDP (port+1)
	TCP     string // plain TLS/TCP (:8443)
	TCP2    string // secondary TLS/TCP (:8444)
	Reality string // VLESS+Reality (:443)
}

// TestAllServers runs all per-port connectivity checks for every predefined
// server and streams results through the returned channel. The channel is
// closed when all tests finish. Servers are tested concurrently; within a
// server the five probes also run concurrently.
func TestAllServers() <-chan ServerTestResult {
	ch := make(chan ServerTestResult, len(predefinedServers))
	go func() {
		done := make(chan struct{}, len(predefinedServers))
		for _, s := range predefinedServers {
			s := s
			go func() {
				host, _, _ := net.SplitHostPort(s.addr)
				res := ServerTestResult{Name: s.name, Addr: s.addr}
				var wg [5]chan string
				for i := range wg {
					wg[i] = make(chan string, 1)
				}
				go func() { wg[0] <- testProbeUDP(s.addr) }()
				go func() { wg[1] <- testProbeUDP(portPlusOne(s.addr)) }()
				go func() { wg[2] <- testTCPConnect(net.JoinHostPort(host, tlsPort)) }()
				go func() { wg[3] <- testTCPConnect(net.JoinHostPort(host, tls2Port)) }()
				go func() { wg[4] <- testReality(net.JoinHostPort(host, realityPort)) }()
				res.UDP, res.UDP2 = <-wg[0], <-wg[1]
				res.TCP, res.TCP2 = <-wg[2], <-wg[3]
				res.Reality = <-wg[4]
				ch <- res
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

// portPlusOne returns addr with its port incremented by one (host:port+1).
func portPlusOne(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(host, strconv.Itoa(p+1))
}

// testProbeUDP sends a FrameListHubs request and waits up to 3 s for any
// response. Uses our own protocol so the test is meaningful even behind NAT.
func testProbeUDP(addr string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tr, err := transport.DialUDP(addr)
	if err != nil {
		return "✗"
	}
	defer tr.Close()

	if err := tr.Send(transport.Frame{Data: listHubsFrame()}); err != nil {
		return "✗"
	}
	if _, err := tr.Recv(ctx); err != nil {
		if ctx.Err() != nil {
			return "✗"
		}
		return "✗"
	}
	return "✓"
}

// testTCPConnect dials a TCP port with a 3 s timeout (reachability only).
func testTCPConnect(addr string) string {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "✗"
		}
		return "✗"
	}
	conn.Close()
	return "✓"
}

// testReality performs a full Reality handshake (using a public key from the
// embedded pool and the default SNI) and then sends a FrameListHubs probe.
// A genuine Reality server replies; a prober-fallback (real dest site) does
// not, so this distinguishes a working Reality endpoint from plain HTTPS.
func testReality(addr string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pub := transport.RandomPoolPublicKey()
	if pub == "" {
		return "✗"
	}
	tr, err := transport.DialReality(ctx, transport.RealityClientParams{
		Addr:        addr,
		SNI:         "www.microsoft.com",
		PublicKey:   pub,
		Fingerprint: "chrome",
	})
	if err != nil {
		return "✗"
	}
	defer tr.Close()

	if err := tr.Send(transport.Frame{Data: listHubsFrame()}); err != nil {
		return "✗"
	}
	if _, err := tr.Recv(ctx); err != nil {
		if ctx.Err() != nil {
			return "✗" // handshake ok but no reply — likely a Reality prober-fallback, not our server
		}
		return "✗"
	}
	return "✓"
}

func listHubsFrame() []byte {
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameListHubs}.Marshal(hdr)
	return hdr
}
