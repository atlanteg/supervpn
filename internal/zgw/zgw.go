// Package zgw implements BMW ZGW (Central Gateway) discovery over the
// ENET link-local network.
//
// Two-stage discovery:
//
//  1. Interface stage: as soon as a 169.254.x.x NIC is detected, report it
//     immediately (VIN = "").  This matches Remote Enet behaviour — the car
//     appears the moment the cable is connected, before any UDP exchange.
//
//  2. ZGW stage: broadcast 4 zero bytes to 169.254.255.255:6811 and wait for
//     a UDP response containing a 17-char VIN.  Updates the display with the
//     real ZGW IP and VIN when confirmed.
//
// Probe sockets:
//   - Persistent rx bound to 0.0.0.0:6811 (SO_REUSEADDR) — catches ZGW
//     responses directed to port 6811 AND any unsolicited ZGW announcements.
//   - Short-lived sockets bound to each 169.254.x.x NIC — force the broadcast
//     out the correct interface on multi-homed machines.
//   - The rx socket itself also sends a probe (source port = 6811) so the
//     ZGW's unicast reply is directed back to port 6811.
package zgw

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/atlanteg/supervpn/internal/bridge"
)

const (
	zgwPort  = 6811
	interval = 5 * time.Second
	// zgwSilenceTimeout: if no ZGW packet for this long after one was seen, revert to interface-only state.
	zgwSilenceTimeout = 2 * interval
)

// vinRe matches a valid VIN: 17 chars, no I/O/Q (ISO 3779).
var vinRe = regexp.MustCompile(`[A-HJ-NPR-Z0-9]{17}`)

// Info holds the result of a discovery step.
// VIN == "" means the 169.254 interface was found but ZGW has not responded yet.
type Info struct {
	IP  string
	VIN string
}

func (i *Info) String() string {
	if i == nil {
		return ""
	}
	if i.VIN == "" {
		return i.IP
	}
	return i.IP + "  " + i.VIN
}

// scanIfaces returns the first detected 169.254 interface as a bare Info
// (no VIN), or nil if none found.  skipName is the name of our own VPN tunnel
// adapter (e.g. "supervpn") which must not be mistaken for a BMW connection.
func scanIfaces(skipName string) *Info {
	ifaces, err := bridge.DetectLinkLocal()
	if err != nil {
		log.Printf("zgw: DetectLinkLocal: %v", err)
		return nil
	}
	for _, iface := range ifaces {
		if skipName != "" && iface.Name == skipName {
			continue // skip our own VPN tunnel adapter
		}
		if iface.Addr != nil {
			log.Printf("zgw: 169.254 interface found: %s (%s)", iface.Name, iface.Addr)
			return &Info{IP: iface.Addr.String()}
		}
	}
	return nil
}


// doProbes sends the 4-byte ZGW discovery request on all available paths.
// skipName is the VPN tunnel adapter name to exclude from per-interface probing.
func doProbes(rx *net.UDPConn, skipName string) {
	// Both broadcast forms: limited (255.255.255.255) and directed link-local
	// subnet broadcast (169.254.255.255).  Some ZGW firmware only responds to
	// the directed form.
	bcastLimited  := &net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: zgwPort}
	bcastDirected := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: zgwPort}
	probe := []byte{0x00, 0x00, 0x00, 0x00}

	// From rx socket (source port = zgwPort) so ZGW unicast reply lands on 6811.
	_ = rx.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = rx.WriteToUDP(probe, bcastLimited)
	_, _ = rx.WriteToUDP(probe, bcastDirected)

	// Per-interface sockets to force broadcast out the correct NIC.
	ifaces, err := bridge.DetectLinkLocal()
	if err != nil || len(ifaces) == 0 {
		return
	}
	for _, iface := range ifaces {
		if iface.Addr == nil {
			continue
		}
		if skipName != "" && iface.Name == skipName {
			continue // don't probe through our own VPN tunnel
		}
		sc, err := openSendConn(iface.Addr.String())
		if err != nil {
			log.Printf("zgw: openSendConn(%s): %v", iface.Addr, err)
			continue
		}
		_ = sc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = sc.WriteToUDP(probe, bcastLimited)
		_, _ = sc.WriteToUDP(probe, bcastDirected)
		log.Printf("zgw: broadcast from %s", iface.Addr)
		sc.Close()
	}
}

// Run detects 169.254 interfaces and discovers the BMW ZGW.
// skipIfaceName is the name of the local VPN tunnel adapter (e.g. "supervpn")
// that should be excluded from BMW interface detection and probing — otherwise
// the VPN adapter itself would be mistaken for a BMW ENET connection.
// onChange is called on a background goroutine whenever the result changes;
// callers must dispatch to their UI thread as appropriate.
func Run(ctx context.Context, skipIfaceName string, onChange func(*Info)) {
	var (
		mu       sync.Mutex
		last     *Info
		first    = true
		lastSeen time.Time // last time a ZGW UDP packet arrived
	)

	notify := func(info *Info) {
		mu.Lock()
		defer mu.Unlock()
		changed := first || !equal(last, info)
		if changed {
			first = false
			last = info
			onChange(info)
		}
	}

	// Stage 1: report interface immediately, before any UDP exchange.
	notify(scanIfaces(skipIfaceName))

	rx, err := openRecvConn(zgwPort)
	if err != nil {
		log.Printf("zgw: openRecvConn(:%d) failed: %v — VIN discovery disabled, interface-only mode", zgwPort, err)
		// Keep refreshing interface presence even without UDP.
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				notify(scanIfaces(skipIfaceName))
			}
		}
	}
	log.Printf("zgw: listening on 0.0.0.0:%d", zgwPort)

	go func() {
		<-ctx.Done()
		rx.Close()
	}()

	// Receive loop.
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = rx.SetReadDeadline(time.Now().Add(interval + time.Second))
			n, addr, err := rx.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			preview := n
			if preview > 32 {
				preview = 32
			}
			log.Printf("zgw: recv %d bytes from %s: % x", n, addr, buf[:preview])

			vin := vinRe.Find(buf[:n])
			if vin == nil {
				log.Printf("zgw: no VIN in packet from %s", addr)
				continue
			}
			log.Printf("zgw: ZGW at %s  VIN=%s", addr.IP, string(vin))
			mu.Lock()
			lastSeen = time.Now()
			mu.Unlock()
			notify(&Info{IP: addr.IP.String(), VIN: string(vin)})
		}
	}()

	// Periodic probe + interface re-scan.
	doProbes(rx, skipIfaceName)

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Re-scan interfaces first so the UI is updated even without ZGW response.
			ifaceInfo := scanIfaces(skipIfaceName)

			doProbes(rx, skipIfaceName)

			mu.Lock()
			seen := lastSeen
			mu.Unlock()

			if !seen.IsZero() && time.Since(seen) > zgwSilenceTimeout {
				// ZGW was found before but went silent — fall back to interface-only.
				log.Printf("zgw: ZGW silent for >%v — reverting to interface-only", zgwSilenceTimeout)
				notify(ifaceInfo)
			} else if seen.IsZero() {
				// Never got a ZGW response — keep showing interface if present.
				notify(ifaceInfo)
			}
			// If lastSeen is recent, the receive goroutine already called notify with VIN.
		}
	}
}

// Discover is used by the fallback path only.
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
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		if vin := vinRe.Find(buf[:n]); vin != nil {
			return &Info{IP: remoteAddr.IP.String(), VIN: string(vin)}
		}
	}
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

// FormatBMW returns the display string for the UI label.
func FormatBMW(info *Info) string {
	if info == nil {
		return "BMW: not found"
	}
	if info.VIN == "" {
		return fmt.Sprintf("BMW: %s (no ZGW response)", info.IP)
	}
	return fmt.Sprintf("BMW: %s  %s", info.IP, info.VIN)
}
