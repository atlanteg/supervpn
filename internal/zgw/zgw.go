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
// Discovery uses two separate sockets:
//   - A persistent receiver bound to 0.0.0.0:6811 (SO_REUSEADDR) — catches both
//     responses to our probes AND any unsolicited periodic ZGW announcements.
//   - Short-lived senders bound to each 169.254.x.x address to force the broadcast
//     out the correct interface.
package zgw

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/atlanteg/supervpn/internal/bridge"
)

const (
	zgwPort  = 6811
	interval = 5 * time.Second
	// zgwSilenceTimeout: if no ZGW packet arrives for this long, report "not found".
	zgwSilenceTimeout = 2 * interval
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

// sendProbes broadcasts the 4-byte ZGW request on every detected 169.254
// interface.  Each interface gets its own short-lived send socket so the OS
// routes the broadcast out the correct NIC.
func sendProbes() {
	ifaces, err := bridge.DetectLinkLocal()
	if err != nil {
		return
	}
	dst := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: zgwPort}
	probe := []byte{0x00, 0x00, 0x00, 0x00}
	for _, iface := range ifaces {
		if iface.Addr == nil {
			continue
		}
		sc, err := openSendConn(iface.Addr.String())
		if err != nil {
			continue
		}
		_ = sc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = sc.WriteToUDP(probe, dst)
		sc.Close()
	}
}

// Run opens a persistent UDP listener on port zgwPort (SO_REUSEADDR) and
// calls onChange each time the result changes.  A probe broadcast is sent
// immediately and then every interval seconds to solicit a ZGW response; the
// listener also catches any unsolicited periodic ZGW announcements so the BMW
// is found as soon as it sends one — matching Remote Enet's behaviour.
//
// onChange is always called on a background goroutine; callers must dispatch
// to their UI thread as appropriate.
func Run(ctx context.Context, onChange func(*Info)) {
	var (
		mu       sync.Mutex
		last     *Info
		first    = true
		lastSeen time.Time
	)

	notify := func(info *Info) {
		mu.Lock()
		defer mu.Unlock()
		if first || !equal(last, info) {
			first = false
			last = info
			onChange(info)
		}
	}

	rx, err := openRecvConn(zgwPort)
	if err != nil {
		// No persistent listener available; fall back to the old probe-only path.
		runFallback(ctx, onChange)
		return
	}

	// Close the receive socket when the context is cancelled so the read loop
	// unblocks immediately.
	go func() {
		<-ctx.Done()
		rx.Close()
	}()

	// Receive loop: runs for the lifetime of ctx.
	go func() {
		buf := make([]byte, 512)
		for {
			_ = rx.SetReadDeadline(time.Now().Add(interval + time.Second))
			n, addr, err := rx.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// Read timeout — no packet in this window; continue to keep
				// the deadline rolling rather than blocking forever.
				continue
			}
			vin := vinRe.Find(buf[:n])
			if vin == nil {
				continue
			}
			mu.Lock()
			lastSeen = time.Now()
			mu.Unlock()
			notify(&Info{IP: addr.IP.String(), VIN: string(vin)})
		}
	}()

	// Report "not found" immediately so the UI label is populated before the
	// first ZGW packet arrives.
	notify(nil)

	// Send the first probe right away; subsequent probes on every tick.
	sendProbes()

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			sendProbes()
			// If we had found a ZGW but it has gone silent, report "not found".
			mu.Lock()
			seen := lastSeen
			mu.Unlock()
			if !seen.IsZero() && time.Since(seen) > zgwSilenceTimeout {
				notify(nil)
			}
		}
	}
}

// runFallback is the old request-response approach used when openRecvConn
// fails (e.g. port 6811 cannot be opened even with SO_REUSEADDR).
func runFallback(ctx context.Context, onChange func(*Info)) {
	var last *Info
	first := true

	probe := func() {
		info := scanAll()
		if first || !equal(last, info) {
			first = false
			last = info
			onChange(info)
		}
	}
	probe()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			probe()
		}
	}
}

// Discover sends a single ZGW discovery broadcast on the interface with the
// given localIP (a 169.254.x.x address) and waits up to 1500 ms for a response.
// Used only by scanAll (fallback path).
func Discover(localIP string) *Info {
	const timeout = 1500 * time.Millisecond
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(localIP), Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	enableBroadcast(conn)
	_ = conn.SetDeadline(time.Now().Add(timeout))

	broadcast := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: zgwPort}
	if _, err := conn.WriteToUDP([]byte{0x00, 0x00, 0x00, 0x00}, broadcast); err != nil {
		return nil
	}

	buf := make([]byte, 256)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		vin := vinRe.Find(buf[:n])
		if vin != nil {
			return &Info{IP: remoteAddr.IP.String(), VIN: string(vin)}
		}
	}
}

// scanAll tries ZGW discovery on every detected 169.254 interface.
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
func FormatBMW(info *Info) string {
	if info == nil {
		return "BMW: not found"
	}
	return fmt.Sprintf("BMW: %s  %s", info.IP, info.VIN)
}
