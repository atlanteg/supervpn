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
	"log"
	"net"
	"strings"
	"time"
)

// IsExcludedFromBridge reports whether an adapter must NEVER be bridged or probed
// — currently the Radmin VPN virtual adapter (Famatech), which lives on 26.0.0.0/8
// and would corrupt the L2 bridge if captured. Matched by friendly name and (on
// Windows) hardware description, so renaming the connection cannot defeat it.
// This is a HARD exclusion: it applies even to an explicitly selected bridge NIC.
func IsExcludedFromBridge(name string) bool {
	hit := func(s string) bool {
		s = strings.ToLower(s)
		return strings.Contains(s, "radmin") || strings.Contains(s, "famatech")
	}
	return hit(name) || hit(adapterDescription(name))
}

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
		// Radmin VPN (Famatech) and the like must never be a bridge candidate.
		if IsExcludedFromBridge(iface.Name) {
			continue
		}
		// net.FlagUp on Windows only reflects the administrative state. An
		// enabled Ethernet NIC with no cable still gets a 169.254 APIPA address
		// but cannot transmit (pcap_sendpacket failed). Skip adapters that are
		// not operationally up (media-connected). No-op on non-Windows.
		if !ifaceHasLink(iface.Name) {
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
	// MSSClamp caps the TCP MSS of bridged SYN segments so the inner TCP never
	// emits frames that fragment once wrapped in VPN overhead. 0 = disabled.
	// Applied in BOTH directions so a connection is protected regardless of which
	// side (local or a remote peer) originated the SYN or which client clamps.
	MSSClamp uint16
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
		frame = ClampTCPMSS(frame, b.MSSClamp)
		if err := b.send(frame); err != nil {
			return fmt.Errorf("bridge: send upstream: %w", err)
		}
	}
}

// RunDownstream injects frames received from the server into the local network interface.
// frames channel is closed when the connection is lost.
func (b *Bridge) RunDownstream(ctx context.Context, frames <-chan []byte) error {
	var dropped uint64
	var lastLog time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame, ok := <-frames:
			if !ok {
				return io.EOF
			}
			frame = ClampTCPMSS(frame, b.MSSClamp)
			if err := b.framer.WriteFrame(frame); err != nil {
				// A single inject failure (e.g. the bridged NIC momentarily has
				// no link, or cannot send raw L2) must NOT tear down the whole
				// VPN session — that turned one dropped frame into an endless
				// reconnect loop. Drop the frame and keep going; the session
				// still ends if the read/transport side dies. Rate-limit the log.
				dropped++
				if time.Since(lastLog) > 5*time.Second {
					log.Printf("bridge: downstream inject failing, dropped %d frame(s): %v", dropped, err)
					lastLog = time.Now()
				}
			}
		}
	}
}

// Inject delivers a frame received from the server into the local interface.
func (b *Bridge) Inject(frame []byte) error {
	return b.framer.WriteFrame(frame)
}
