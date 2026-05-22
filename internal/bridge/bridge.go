// Package bridge implements the client-side L2 bridge.
//
// The bridge detects network interfaces with 169.254.0.0/16 (link-local / APIPA)
// addressing and transparently forwards all Ethernet frames from those interfaces
// to the supervpn server hub, and vice versa — without altering IP headers.
//
// Platform-specific capture is done via pkg/tun (WinTun on Windows, TAP on Linux).
package bridge

import (
	"context"
	"fmt"
	"io"
	"net"
)

// LinkLocalNet is the 169.254.0.0/16 network we scan for.
var LinkLocalNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("169.254.0.0/16")
	return n
}()

// Interface represents a detected local interface to bridge.
type Interface struct {
	Name   string
	HWAddr net.HardwareAddr
	Addr   net.IP // first 169.254 address found on this interface
}

// DetectLinkLocal returns all network interfaces that have at least one
// 169.254.0.0/16 address. These are the candidates for bridging.
func DetectLinkLocal() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("bridge: list interfaces: %w", err)
	}
	var result []Interface
	for _, iface := range ifaces {
		// Skip interfaces that are not up — a disabled/disconnected NIC
		// may still have a 169.254 APIPA address assigned by Windows,
		// and bridging it would be a no-op or cause confusion.
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if LinkLocalNet.Contains(ip) {
				result = append(result, Interface{
					Name:   iface.Name,
					HWAddr: iface.HardwareAddr,
					Addr:   ip,
				})
				break
			}
		}
	}
	return result, nil
}

// Framer is the platform-specific L2 frame capture/inject interface.
// Implemented in pkg/tun for each OS.
type Framer interface {
	// ReadFrame blocks until an Ethernet frame is available.
	ReadFrame(ctx context.Context) ([]byte, error)
	// WriteFrame injects an Ethernet frame into the local network stack.
	WriteFrame(frame []byte) error
	Close() error
}

// Config holds the parameters for creating a Bridge.
type Config struct {
	Iface     Interface
	Framer    Framer
	SessionID uint32
	HubID     uint16
	// Send sends an encrypted+framed packet to the server.
	Send func(plainFrame []byte) error
}

// Bridge connects a local Framer (tap interface) to the remote hub.
type Bridge struct {
	iface     Interface
	framer    Framer
	send      func(frame []byte) error // sends frame to server
	SessionID uint32
	HubID     uint16
}

func New(iface Interface, framer Framer, send func(frame []byte) error) *Bridge {
	return &Bridge{iface: iface, framer: framer, send: send}
}

// RunUpstream reads frames from local interface and sends to server.
// Returns the error that caused the loop to stop so the caller can reconnect.
func (b *Bridge) RunUpstream(ctx context.Context) error {
	for {
		frame, err := b.framer.ReadFrame(ctx)
		if err != nil {
			return err
		}
		if err := b.send(frame); err != nil {
			return fmt.Errorf("bridge: send upstream: %w", err)
		}
	}
}

// RunDownstream injects frames received from the server into the local network interface.
// frames channel is closed when the connection is lost.
func (b *Bridge) RunDownstream(ctx context.Context, frames <-chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame, ok := <-frames:
			if !ok {
				return io.EOF
			}
			if err := b.framer.WriteFrame(frame); err != nil {
				return err
			}
		}
	}
}

// Inject delivers a frame received from the server into the local interface.
func (b *Bridge) Inject(frame []byte) error {
	return b.framer.WriteFrame(frame)
}
