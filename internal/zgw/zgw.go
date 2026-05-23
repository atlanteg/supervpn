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
// Discovery strategy (two complementary probes on every tick):
//
//  1. Send from the persistent rx socket (0.0.0.0:6811, SO_REUSEADDR).
//     Source port == 6811, so the ZGW's unicast response is also directed to
//     port 6811 — where the rx loop is already listening.
//
//  2. Send from a short-lived socket bound to each 169.254.x.x interface address.
//     This forces the broadcast out the correct NIC on multi-homed hosts.
//     Broadcast responses (169.254.255.255:6811) are caught by the rx socket.
//     Unicast responses to the ephemeral source port are NOT caught this way,
//     but probe #1 already covers that case.
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

// doProbes sends the 4-byte ZGW request:
//   - from rx (0.0.0.0:6811) so the ZGW's unicast reply lands on port 6811
//   - from each detected 169.254.x.x interface to force the broadcast
//     out the correct NIC on multi-homed machines
func doProbes(rx *net.UDPConn) {
	dst := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: zgwPort}
	probe := []byte{0x00, 0x00, 0x00, 0x00}

	// Probe 1: from rx socket (source port = zgwPort).
	_ = rx.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := rx.WriteToUDP(probe, dst); err != nil {
		log.Printf("zgw: probe from rx socket failed: %v", err)
	}

	// Probe 2: per-interface, to ensure the broadcast exits the correct NIC.
	ifaces, err := bridge.DetectLinkLocal()
	if err != nil {
		log.Printf("zgw: DetectLinkLocal: %v", err)
		return
	}
	if len(ifaces) == 0 {
		log.Printf("zgw: no 169.254 interfaces found — BMW not reachable")
		return
	}
	for _, iface := range ifaces {
		if iface.Addr == nil {
			continue
		}
		sc, err := openSendConn(iface.Addr.String())
		if err != nil {
			log.Printf("zgw: openSendConn(%s): %v", iface.Addr, err)
			continue
		}
		_ = sc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = sc.WriteToUDP(probe, dst)
		sc.Close()
		log.Printf("zgw: probe sent from %s → %s", iface.Addr, dst)
	}
}

// Run opens a persistent UDP listener on port zgwPort (SO_REUSEADDR) and
// calls onChange each time the result changes.  Probes are sent immediately
// and then every interval seconds; the listener also catches unsolicited
// periodic ZGW announcements (matching Remote Enet behaviour).
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
		log.Printf("zgw: openRecvConn(:%d) failed: %v — falling back to request-response mode", zgwPort, err)
		runFallback(ctx, onChange)
		return
	}
	log.Printf("zgw: listening on 0.0.0.0:%d", zgwPort)

	// Close the receive socket when the context is cancelled so the read loop
	// unblocks immediately.
	go func() {
		<-ctx.Done()
		rx.Close()
	}()

	// Receive loop: runs for the lifetime of ctx.
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = rx.SetReadDeadline(time.Now().Add(interval + time.Second))
			n, addr, err := rx.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// Read timeout — no packet; keep rolling the deadline.
				continue
			}
			// Log every incoming packet for diagnostics (first 32 bytes).
			preview := n
			if preview > 32 {
				preview = 32
			}
			log.Printf("zgw: recv %d bytes from %s: % x", n, addr, buf[:preview])

			vin := vinRe.Find(buf[:n])
			if vin == nil {
				log.Printf("zgw: packet from %s has no VIN match", addr)
				continue
			}
			log.Printf("zgw: found ZGW at %s  VIN=%s", addr.IP, string(vin))
			mu.Lock()
			lastSeen = time.Now()
			mu.Unlock()
			notify(&Info{IP: addr.IP.String(), VIN: string(vin)})
		}
	}()

	// Report "not found" immediately so the UI label is populated before the
	// first ZGW packet arrives.
	notify(nil)

	// First probe immediately; subsequent probes on every tick.
	doProbes(rx)

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			doProbes(rx)
			// If we had found a ZGW but it has gone silent, report "not found".
			mu.Lock()
			seen := lastSeen
			mu.Unlock()
			if !seen.IsZero() && time.Since(seen) > zgwSilenceTimeout {
				log.Printf("zgw: ZGW silent for >%v — reporting not found", zgwSilenceTimeout)
				notify(nil)
			}
		}
	}
}

// runFallback is the classic request-response approach used when openRecvConn
// fails.  Each Discover call uses its own socket: send + read on the same
// socket so the reply lands on the correct (ephemeral) source port.
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

	buf := make([]byte, 4096)
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
