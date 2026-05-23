// Package zgw implements BMW ZGW (Central Gateway) discovery over the
// ENET link-local network.
//
// The ZGW discovery protocol (reverse-engineered from ZGW_SEARCH_3.0.exe and
// Remote Enet_ssh.exe):
//
//   - Transport: UDP broadcast to 169.254.255.255:6811
//   - Request:   4 zero bytes  (\x00\x00\x00\x00)
//   - Response:  variable-length; contains VIN as the first 17-byte sequence
//     matching [A-HJ-NPR-Z0-9]{17}; source IP is the ZGW address.
//
// The socket is bound to the local 169.254.x.x address so the broadcast
// is sent on the correct link-local interface (important on multi-NIC hosts).
package zgw

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/atlanteg/supervpn/internal/bridge"
)

const (
	zgwPort    = 6811
	zgwTimeout = 1500 * time.Millisecond
	interval   = 5 * time.Second
)

// vinRe matches a valid VIN: 17 chars, no I/O/Q (ISO 3779).
var vinRe = regexp.MustCompile(`[A-HJ-NPR-Z0-9]{17}`)

// Info holds the result of a successful ZGW discovery.
type Info struct {
	IP  string
	VIN string
}

// String returns a compact display string, e.g. "169.254.1.200  WBA1234567890ABCD".
func (i *Info) String() string {
	if i == nil {
		return ""
	}
	return i.IP + "  " + i.VIN
}

// Discover sends a single ZGW discovery broadcast on the interface with the
// given localIP (a 169.254.x.x address) and waits up to zgwTimeout for a
// response.  Returns nil if the ZGW does not respond within the deadline.
func Discover(localIP string) *Info {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(localIP), Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Windows requires SO_BROADCAST to be set explicitly; without it the packet
	// is silently dropped by Winsock before it reaches the wire.
	enableBroadcast(conn)

	_ = conn.SetDeadline(time.Now().Add(zgwTimeout))

	broadcast := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: zgwPort}
	if _, err := conn.WriteToUDP([]byte{0x00, 0x00, 0x00, 0x00}, broadcast); err != nil {
		return nil
	}

	buf := make([]byte, 256)
	n, remoteAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil // timeout or no ZGW on this segment
	}

	vin := vinRe.Find(buf[:n])
	if vin == nil {
		return nil
	}
	return &Info{IP: remoteAddr.IP.String(), VIN: string(vin)}
}

// Run scans for 169.254.x.x interfaces every interval and calls onChange
// each time the result changes (found → not found, not found → found, or
// VIN/IP changes).  The first call always fires onChange so the label is
// populated immediately on startup.  Stops when ctx is cancelled.
//
// onChange is always called on a background goroutine; callers must
// dispatch to their UI thread as appropriate.
func Run(ctx context.Context, onChange func(*Info)) {
	var last *Info
	first := true
	tick := time.NewTicker(interval)
	defer tick.Stop()

	// Probe immediately on first call so the UI doesn't show a blank for 5 s.
	probe := func() {
		info := scanAll()
		if first || !equal(last, info) {
			first = false
			last = info
			onChange(info)
		}
	}
	probe()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			probe()
		}
	}
}

// scanAll tries ZGW discovery on every detected 169.254 interface and
// returns the first successful result, or nil.
func scanAll() *Info {
	ifaces, err := bridge.DetectLinkLocal()
	if err != nil || len(ifaces) == 0 {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Addr == nil {
			continue
		}
		if info := Discover(iface.Addr.String()); info != nil {
			return info
		}
	}
	return nil
}

func equal(a, b *Info) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.IP == b.IP && a.VIN == b.VIN
}

// FormatBMW returns the display string shown in the UI status area.
// Always returns a non-empty string so the label row stays visible.
func FormatBMW(info *Info) string {
	if info == nil {
		return "BMW: not found"
	}
	return fmt.Sprintf("BMW: %s  %s", info.IP, info.VIN)
}
