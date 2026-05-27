// Package bmwzgw implements BMW ZGW (Central Gateway) discovery over the
// ENET link-local network.
//
// # Two-stage discovery
//
//  1. Interface stage: as soon as a 169.254.x.x NIC is detected, [Run]
//     fires onChange immediately with VIN == "".  This matches Remote Enet
//     behaviour — the car appears the moment the cable is plugged in, before
//     any UDP exchange completes.
//
//  2. ZGW stage: the package broadcasts a 6-byte probe to
//     255.255.255.255:6811 and 169.254.255.255:6811 and waits for a UDP
//     response containing a 17-char VIN.  Once confirmed, onChange is fired
//     again with the real ZGW IP, VIN, decoded model name, and ISTA target.
//
// # Minimal integration
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	bmwzgw.Run(ctx, "", func(info *bmwzgw.Info) {
//	    if info == nil {
//	        fmt.Println("BMW: not found")
//	        return
//	    }
//	    fmt.Println(bmwzgw.FormatBMW(info))
//	    // "BMW: 169.254.138.176  WBA8X51000CF40263  F34 320i xDrive  F020"
//	})
//
// # skipIfaceName
//
// Pass the name of your own virtual/VPN adapter (e.g. "supervpn", "tap0") as
// skipIfaceName so the package does not mistake it for a BMW ENET connection.
// Pass "" to skip nothing.
//
// # Probe sockets
//
//   - Persistent RX socket bound to 0.0.0.0:6811 (SO_REUSEADDR) — catches
//     any ZGW packet directed to port 6811 regardless of source interface.
//   - Short-lived sockets bound to each 169.254.x.x NIC — forces the
//     broadcast out the correct interface on multi-homed machines.  Each
//     socket stays alive for 2 s after sending so the ZGW's unicast reply
//     (directed to the ephemeral source port) is not dropped.
//
// # ZGW response format
//
// The ZGW responds with a UDP payload of the form:
//
//	00 00 00 32 00 11 DIAGADR<hex> BMWMAC<12hex> BMWVIN<17charVIN>
//
// Example:
//
//	DIAGADR10BMWMAC48C58D90515CBMWVINWBA8X51000CF40263
//
// DIAGADR is a hex number representing half the ISTA ECU target address:
// "10" → 0x10×2 = 0x20 → target "F020".
package bmwzgw

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	zgwPort  = 6811
	interval = 5 * time.Second
	// zgwSilenceTimeout: if no ZGW packet arrives for this long after one was
	// seen, revert to interface-only state (car may have been disconnected).
	zgwSilenceTimeout = 2 * interval
	// probeRecvWindow: how long per-interface sockets stay open after sending
	// to collect the ZGW's unicast reply directed to the ephemeral source port.
	probeRecvWindow = 2 * time.Second
)

// vinRe extracts VIN from ZGW response payload.  Anchoring to the "BMWVIN"
// keyword avoids false matches on other 17-char sequences such as
// "AGADR10BMWMAC48C5" that appear earlier in the same payload.
var vinRe = regexp.MustCompile(`BMWVIN([A-HJ-NPR-Z0-9]{17})`)

// diagadrRe extracts the DIAGADR hex field.  Anchoring to the following
// "BMWMAC" keyword prevents the greedy match from consuming the 'B' in
// "BMWMAC" (which is a valid hex digit), which would corrupt the target value.
// Example: "DIAGADR10BMWMAC..." → captures "10".
var diagadrRe = regexp.MustCompile(`DIAGADR([0-9A-Fa-f]+)BMWMAC`)

// ── VIN decode tables ────────────────────────────────────────────────────────

type bmwModelEntry struct {
	chassis string // platform code, e.g. "F34"
	series  string // "3" (single digit) or "X5"/"M3" (named model)
}

// bmwTypeKeys maps VIN[3] (BMW Baumuster / type key) to chassis + series.
// Covers E-series (pre-2011), F-series (2011–2019), and G-series (2019–).
var bmwTypeKeys = map[byte]bmwModelEntry{
	// E-series
	'1': {"E87", "1"},  // 1 Series E87/E81
	'9': {"E90", "3"},  // 3 Series E90/E91
	// F-series
	'2': {"F20", "1"},  // 1 Series F20/F21
	'3': {"F30", "3"},  // 3 Series F30 sedan / F31 touring
	'4': {"F32", "4"},  // 4 Series F32 coupe / F33 cabrio / F36 gran coupe
	'5': {"F10", "5"},  // 5 Series F10 sedan / F11 touring
	'6': {"F12", "6"},  // 6 Series F12 cabrio / F13 coupe / F06 gran coupe
	'7': {"F01", "7"},  // 7 Series F01 / F02 long wheelbase
	'8': {"F34", "3"},  // 3 Series Gran Turismo F34
	'A': {"F15", "X5"}, // X5 F15
	'B': {"F16", "X6"}, // X6 F16
	'C': {"F25", "X3"}, // X3 F25
	'D': {"F26", "X4"}, // X4 F26
	'E': {"F45", "2"},  // 2 Series Active Tourer F45 / Gran Tourer F46
	'F': {"F48", "X1"}, // X1 F48
	'G': {"F39", "X2"}, // X2 F39
	// G-series
	'H': {"G20", "3"},  // 3 Series G20 sedan / G21 touring
	'J': {"G30", "5"},  // 5 Series G30 sedan / G31 touring
	'K': {"G11", "7"},  // 7 Series G11 / G12 long wheelbase
	'L': {"G01", "X3"}, // X3 G01
	'M': {"G02", "X4"}, // X4 G02
	'N': {"G05", "X5"}, // X5 G05
	'P': {"G06", "X6"}, // X6 G06
	'R': {"G07", "X7"}, // X7 G07
	'S': {"G29", "Z4"}, // Z4 G29
	'T': {"G42", "2"},  // 2 Series Coupe G42
	'U': {"G80", "M3"}, // M3 G80 / M3 Touring G81
	'V': {"G82", "M4"}, // M4 G82 coupe / G83 cabrio
	'W': {"G26", "4"},  // 4 Series Gran Coupe G26
	'X': {"G22", "4"},  // 4 Series G22 coupe / G23 cabrio
	'Y': {"G15", "8"},  // 8 Series G15 coupe / G14 cabrio
	'Z': {"G16", "8"},  // 8 Series Gran Coupe G16
}

// bmwEngineCodes maps VIN[5] to the engine/fuel displacement suffix.
var bmwEngineCodes = map[byte]string{
	'0': "16i",
	'1': "18i", '2': "20d", '3': "30d", '4': "35i",
	'5': "20i", '6': "40i", '7': "35d", '8': "40d",
	'9': "50i",
	'A': "16d", 'B': "18d", 'C': "20d", 'D': "25d",
	'E': "30i", 'F': "M",   'G': "M",   'H': "25e",
	'J': "30e", 'K': "45e", 'L': "25i", 'N': "28i",
	'P': "35i", 'R': "28d", 'S': "M",   'T': "30i",
	'U': "30i", 'V': "40i", 'W': "50e", 'X': "45e",
	'Y': "M",   'Z': "60i",
}

// decodeVIN returns the chassis code and human-readable model label from a
// 17-char BMW VIN.  Returns empty strings for unrecognised type keys.
//
// Examples:
//
//	"WBA8X51000CF40263" → chassis "F34", model "F34 320i xDrive"
//	"WBA3A51090F123456" → chassis "F30", model "F30 320i"
//	"WBSGG910X0CY12345" → chassis "G82", model "G82 M4"
func decodeVIN(vin string) (chassis, model string) {
	if len(vin) < 17 {
		return "", ""
	}
	entry, ok := bmwTypeKeys[vin[3]]
	if !ok {
		return "", ""
	}
	chassis = entry.chassis
	eng := bmwEngineCodes[vin[5]] // "" if unknown

	var drive string
	if vin[4] == 'X' {
		drive = "xDrive"
	}

	if len(entry.series) == 1 {
		// Single-digit series: "F34" + " " + "3" + "20i" = "F34 320i"
		model = chassis + " " + entry.series
		if eng != "" {
			model += eng
		}
	} else {
		// Named model (X1–X7, Z4, M3, M4, 8…): space-separated.
		// M3/M4: engine tag is already "M", same as the series name — skip it.
		model = chassis + " " + entry.series
		if eng != "" && eng != "M" {
			model += " " + eng
		}
	}
	if drive != "" {
		model += " " + drive
	}
	return chassis, model
}

// diagadrToTarget converts the DIAGADR hex string to the BMW ISTA target ID.
// The ZGW DIAGADR is half the ISTA ECU target address:
//
//	"10" → 0x10 × 2 = 0x20 → "F020"
//	"18" → 0x18 × 2 = 0x30 → "F030"
func diagadrToTarget(hexStr string) string {
	v, err := strconv.ParseInt(hexStr, 16, 64)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("F%03X", v*2)
}

// ── Public API ───────────────────────────────────────────────────────────────

// Info holds the result of one discovery step.
//
// When VIN == "" the 169.254 interface was found but the ZGW has not yet
// responded — useful for showing "cable connected" before VIN is known.
// When VIN != "" all fields are populated (Model/Target may be empty if the
// VIN type key or DIAGADR is not recognised).
type Info struct {
	IP      string // ZGW or interface IP, e.g. "169.254.138.176"
	MAC     string // ZGW MAC address, e.g. "48:C5:8D:90:51:5C"; empty until ZGW responds
	VIN     string // 17-char VIN, e.g. "WBA8X51000CF40263"; empty until ZGW responds
	Model   string // decoded model label, e.g. "F34 320i xDrive"; empty if not recognised
	Chassis string // chassis code, e.g. "F34"; empty if not recognised
	Target  string // ISTA target, e.g. "F020"; empty if DIAGADR absent
}

// String returns a compact one-line summary of the discovery result.
func (i *Info) String() string {
	if i == nil {
		return ""
	}
	if i.VIN == "" {
		return i.IP
	}
	s := i.IP + "  " + i.VIN
	if i.Model != "" {
		s += "  " + i.Model
	}
	if i.Target != "" {
		s += "  " + i.Target
	}
	return s
}

// FormatBMW returns a display-ready label suitable for a UI status field.
//
// Examples:
//
//	nil                   → "BMW: not found"
//	VIN==""               → "BMW: 169.254.1.1 (no ZGW response)"
//	VIN set, model known  → "BMW: 169.254.138.176  WBA8X51000CF40263  F34 320i xDrive  F020"
func FormatBMW(info *Info) string {
	if info == nil {
		return "BMW: not found"
	}
	if info.VIN == "" {
		return fmt.Sprintf("BMW: %s (no ZGW response)", info.IP)
	}
	s := fmt.Sprintf("BMW: %s  %s", info.IP, info.VIN)
	if info.Model != "" {
		s += "  " + info.Model
	}
	if info.Target != "" {
		s += "  " + info.Target
	}
	return s
}

// Run continuously discovers BMW ZGW gateways on 169.254.x.x interfaces.
//
// skipIfaceName is the name of a virtual/VPN adapter that should be excluded
// from detection (e.g. "supervpn", "tap0").  Pass "" to skip nothing.
//
// onChange is called on a background goroutine whenever the discovery result
// changes.  Callers must dispatch to their own UI thread if needed.
// onChange(nil) means no BMW interface is present.
//
// Run blocks until ctx is cancelled.
func Run(ctx context.Context, skipIfaceName string, onChange func(*Info)) {
	var (
		mu       sync.Mutex
		last     *Info
		first    = true
		lastSeen time.Time
	)

	notify := func(info *Info) {
		mu.Lock()
		defer mu.Unlock()
		if first || !infoEqual(last, info) {
			first = false
			last = info
			onChange(info)
		}
	}

	processPacket := func(buf []byte, addr *net.UDPAddr) {
		m := vinRe.FindSubmatch(buf)
		if m == nil {
			log.Printf("bmwzgw: no VIN in packet from %s", addr)
			return
		}
		vin := string(m[1])

		var target, chassis, model, mac string
		if dm := diagadrRe.FindSubmatch(buf); dm != nil {
			target = diagadrToTarget(string(dm[1]))
		}
		if mm := macRe.FindSubmatch(buf); mm != nil {
			mac = formatMAC(string(mm[1]))
		}
		chassis, model = decodeVIN(vin)

		log.Printf("bmwzgw: ZGW at %s  VIN=%s  target=%s  model=%s", addr.IP, vin, target, model)
		mu.Lock()
		lastSeen = time.Now()
		mu.Unlock()
		notify(&Info{
			IP:      addr.IP.String(),
			MAC:     mac,
			VIN:     vin,
			Model:   model,
			Chassis: chassis,
			Target:  target,
		})
	}

	// Stage 1: report interface immediately, before any UDP exchange.
	notify(scanIfaces(skipIfaceName))

	rx, err := openRecvConn(zgwPort)
	if err != nil {
		log.Printf("bmwzgw: openRecvConn(:%d) failed: %v — interface-only mode", zgwPort, err)
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
	log.Printf("bmwzgw: listening on 0.0.0.0:%d", zgwPort)

	go func() {
		<-ctx.Done()
		rx.Close()
	}()

	// Persistent receive loop on port 6811.
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
			log.Printf("bmwzgw: recv %d bytes from %s: % x", n, addr, buf[:preview])
			processPacket(buf[:n], addr)
		}
	}()

	// First probe + periodic re-scan loop.
	doProbes(rx, skipIfaceName, processPacket)

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			ifaceInfo := scanIfaces(skipIfaceName)
			doProbes(rx, skipIfaceName, processPacket)

			mu.Lock()
			seen := lastSeen
			mu.Unlock()

			if !seen.IsZero() && time.Since(seen) > zgwSilenceTimeout {
				log.Printf("bmwzgw: ZGW silent for >%v — reverting to interface-only", zgwSilenceTimeout)
				notify(ifaceInfo)
			} else if seen.IsZero() {
				notify(ifaceInfo)
			}
		}
	}
}

// Discover performs a one-shot synchronous ZGW query from the given localIP
// (must be a 169.254.x.x address on the desired interface).
// Returns nil if no response arrives within 1.5 s.
//
// This is a convenience function for cases where a background goroutine is
// not desired.  For continuous monitoring use [Run].
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
	probe := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x11}
	if _, err := conn.WriteToUDP(probe, broadcast); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		m := vinRe.FindSubmatch(buf[:n])
		if m == nil {
			continue
		}
		vin := string(m[1])
		var target, chassis, model, mac string
		if dm := diagadrRe.FindSubmatch(buf[:n]); dm != nil {
			target = diagadrToTarget(string(dm[1]))
		}
		if mm := macRe.FindSubmatch(buf[:n]); mm != nil {
			mac = formatMAC(string(mm[1]))
		}
		chassis, model = decodeVIN(vin)
		return &Info{
			IP:      remoteAddr.IP.String(),
			MAC:     mac,
			VIN:     vin,
			Model:   model,
			Chassis: chassis,
			Target:  target,
		}
	}
}

// ── Internal helpers ─────────────────────────────────────────────────────────

// macRe extracts the raw 12-hex-char MAC from "BMWMAC<12hex>".
var macRe = regexp.MustCompile(`BMWMAC([0-9A-Fa-f]{12})`)

// formatMAC inserts colons into a 12-char hex string: "48C58D90515C" → "48:C5:8D:90:51:5C".
func formatMAC(s string) string {
	if len(s) != 12 {
		return s
	}
	return s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":" + s[6:8] + ":" + s[8:10] + ":" + s[10:12]
}

// linkLocalNet is the 169.254.0.0/16 network.
var linkLocalNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("169.254.0.0/16")
	return n
}()

// scanIfaces returns a bare Info (no VIN) for the first live 169.254 interface
// found, or nil if none exist.  Interfaces named skipName are excluded.
func scanIfaces(skipName string) *Info {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("bmwzgw: list interfaces: %v", err)
		return nil
	}
	for _, iface := range ifaces {
		if skipName != "" && iface.Name == skipName {
			continue
		}
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
			if linkLocalNet.Contains(ip) {
				log.Printf("bmwzgw: 169.254 interface found: %s (%s)", iface.Name, ip)
				return &Info{IP: ip.String()}
			}
		}
	}
	return nil
}

// doProbes sends the ZGW discovery probe on all available 169.254 interfaces.
func doProbes(rx *net.UDPConn, skipName string, onPacket func([]byte, *net.UDPAddr)) {
	bcastLimited  := &net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: zgwPort}
	bcastDirected := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: zgwPort}
	// 0x0011 = 17 = VIN length — ZGW ignores probes shorter than 6 bytes.
	probe := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x11}

	// Probe from the persistent rx socket (src port = 6811) so the ZGW's
	// unicast reply also lands on the rx socket.
	_ = rx.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = rx.WriteToUDP(probe, bcastLimited)
	_, _ = rx.WriteToUDP(probe, bcastDirected)

	// Per-interface sockets to force the broadcast out the correct NIC on
	// multi-homed machines.
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if skipName != "" && iface.Name == skipName {
			continue
		}
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
			if !linkLocalNet.Contains(ip) {
				continue
			}
			sc, err := openSendConn(ip.String())
			if err != nil {
				log.Printf("bmwzgw: openSendConn(%s): %v", ip, err)
				continue
			}
			_ = sc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = sc.WriteToUDP(probe, bcastLimited)
			_, _ = sc.WriteToUDP(probe, bcastDirected)
			log.Printf("bmwzgw: broadcast from %s", ip)

			// Keep alive for probeRecvWindow to catch the ZGW's unicast reply.
			go func(conn *net.UDPConn) {
				defer conn.Close()
				buf := make([]byte, 4096)
				_ = conn.SetReadDeadline(time.Now().Add(probeRecvWindow))
				for {
					n, addr, err := conn.ReadFromUDP(buf)
					if err != nil {
						return
					}
					preview := n
					if preview > 32 {
						preview = 32
					}
					log.Printf("bmwzgw: recv(ep) %d bytes from %s: % x", n, addr, buf[:preview])
					onPacket(buf[:n], addr)
				}
			}(sc)
		}
	}
}

func infoEqual(a, b *Info) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.IP == b.IP && a.VIN == b.VIN && a.Target == b.Target && a.Model == b.Model
}
