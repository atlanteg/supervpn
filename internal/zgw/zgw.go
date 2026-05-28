// Package zgw implements BMW ZGW (Central Gateway) discovery over the
// ENET link-local network.
//
// Two-stage discovery:
//
//  1. Interface stage: as soon as a 169.254.x.x NIC is detected, report it
//     immediately (VIN = "").  This matches Remote Enet behaviour — the car
//     appears the moment the cable is connected, before any UDP exchange.
//
//  2. ZGW stage: broadcast 4 zero bytes to 255.255.255.255:6811 and
//     169.254.255.255:6811 and wait for a UDP response containing a 17-char
//     VIN.  Updates the display with the real ZGW IP and VIN when confirmed.
//
// Probe sockets:
//   - Persistent rx bound to 0.0.0.0:6811 (SO_REUSEADDR) — catches any ZGW
//     packet directed to port 6811.
//   - Short-lived sockets bound to each 169.254.x.x NIC — force the broadcast
//     out the correct interface on multi-homed machines.  Each socket stays
//     open for 2 s after sending so the ZGW's unicast reply (directed to the
//     ephemeral source port) is not lost.
package zgw

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/atlanteg/supervpn/internal/bridge"
)

const (
	zgwPort  = 6811
	interval = 5 * time.Second
	// zgwSilenceTimeout: if no ZGW packet for this long after one was seen, revert to interface-only state.
	zgwSilenceTimeout = 2 * interval
	// probeRecvWindow: how long per-interface sockets stay open after sending
	// to collect a ZGW unicast reply directed to the ephemeral source port.
	probeRecvWindow = 2 * time.Second
)

// vinRe extracts VIN from ZGW response: looks for "BMWVIN" keyword followed by
// 17 ISO 3779 chars (no I/O/Q).  Anchoring to the keyword avoids false matches
// on other 17-char sequences in the payload (e.g. "AGADR10BMWMAC48C5").
var vinRe = regexp.MustCompile(`BMWVIN([A-HJ-NPR-Z0-9]{17})`)

// diagadrRe extracts the DIAGADR field (hex string) from the ZGW response.
// The field is always immediately followed by "BMWMAC", so we anchor there to
// avoid greedily consuming the 'B' from "BMWMAC" (which is a valid hex digit).
// Example payload: "DIAGADR10BMWMAC..." → captures "10".
var diagadrRe = regexp.MustCompile(`DIAGADR([0-9A-Fa-f]+)BMWMAC`)

// bmwModelEntry maps a BMW type key (VIN[3]) to chassis platform info.
type bmwModelEntry struct {
	chassis string // base chassis code, e.g. "G20" (sedan/coupé)
	tourer  string // estate/wagon variant chassis, e.g. "G21"; "" if N/A
	series  string // series label: single digit "3" or named "X5", "M3"
	fwd     bool   // true = front-wheel drive platform (F45, F48, F39…)
}

// bmwBodyInfo describes the body style and drivetrain encoded in VIN[4].
type bmwBodyInfo struct {
	touring bool // estate/wagon (Touring) body — selects entry.tourer chassis
	xdrive  bool // BMW xDrive all-wheel drive
}

// bmwBodyCodes maps VIN[4] to body style and drivetrain.
// Absent codes → standard sedan/coupé body, rear-wheel drive.
var bmwBodyCodes = map[byte]bmwBodyInfo{
	'X': {false, true},  // xDrive sedan (all series)
	'B': {true, false},  // F31/F11 Touring RWD
	'D': {true, true},   // F31/F11 Touring xDrive
	'E': {true, false},  // G21/G31 Touring RWD
	'N': {true, true},   // G21/G31 Touring xDrive
	'F': {true, false},  // G81 M3 Touring RWD
	'G': {true, true},   // G81 M3 Touring xDrive
}

// bmwTypeKeys maps VIN[3] (BMW Baumuster / type key) to chassis + series.
// Covers E-series (pre-2011), F-series (2011–2019), and G-series (2019–).
var bmwTypeKeys = map[byte]bmwModelEntry{
	// E-series
	'1': {"E87", "", "1", false},    // 1 Series E87/E81
	'9': {"E90", "E91", "3", false}, // 3 Series E90 sedan / E91 Touring
	// F-series
	'2': {"F20", "F21", "1", false}, // 1 Series F20/F21
	'3': {"F30", "F31", "3", false}, // 3 Series F30 sedan / F31 Touring
	'4': {"F32", "", "4", false},    // 4 Series F32 coupé / F33 cabrio / F36 Gran Coupé
	'5': {"F10", "F11", "5", false}, // 5 Series F10 sedan / F11 Touring
	'6': {"F12", "", "6", false},    // 6 Series F12 cabrio / F13 coupé / F06 Gran Coupé
	'7': {"F01", "", "7", false},    // 7 Series F01 SWB / F02 LWB
	'8': {"F34", "", "3", false},    // 3 Series Gran Turismo F34
	'A': {"F15", "", "X5", false},   // X5 F15
	'B': {"F16", "", "X6", false},   // X6 F16
	'C': {"F25", "", "X3", false},   // X3 F25
	'D': {"F26", "", "X4", false},   // X4 F26
	'E': {"F45", "", "2", true},     // 2 Series Active Tourer F45 / Gran Tourer F46 (FWD)
	'F': {"F48", "", "X1", true},    // X1 F48 (FWD)
	'G': {"F39", "", "X2", true},    // X2 F39 (FWD)
	// G-series
	'H': {"G20", "G21", "3", false},  // 3 Series G20 sedan / G21 Touring
	'J': {"G30", "G31", "5", false},  // 5 Series G30 sedan / G31 Touring
	'K': {"G11", "G12", "7", false},  // 7 Series G11 SWB / G12 LWB
	'L': {"G01", "", "X3", false},    // X3 G01
	'M': {"G02", "", "X4", false},    // X4 G02
	'N': {"G05", "", "X5", false},    // X5 G05
	'P': {"G06", "", "X6", false},    // X6 G06
	'R': {"G07", "", "X7", false},    // X7 G07
	'S': {"G29", "", "Z4", false},    // Z4 G29
	'T': {"G42", "", "2", false},     // 2 Series Coupé G42
	'U': {"G80", "G81", "M3", false}, // M3 G80 sedan / G81 Touring
	'V': {"G82", "G83", "M4", false}, // M4 G82 coupé / G83 cabrio
	'W': {"G26", "", "4", false},     // 4 Series Gran Coupé G26
	'X': {"G22", "G23", "4", false},  // 4 Series G22 coupé / G23 cabrio
	'Y': {"G15", "", "8", false},     // 8 Series G15 coupé / G14 cabrio
	'Z': {"G16", "", "8", false},     // 8 Series Gran Coupé G16
}

// bmwEngineCodes maps VIN[5] to the engine/displacement suffix.
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

// decodeVIN returns the chassis code, model label, and — when a match is found
// in the embedded type database — the BMW engine code, body type, and power.
// Returns empty strings for unrecognised type keys.
func decodeVIN(vin string) (chassis, model, engine, body string, powerKW int) {
	if len(vin) < 17 {
		return
	}
	entry, ok := bmwTypeKeys[vin[3]]
	if !ok {
		return
	}

	bodyInfo := bmwBodyCodes[vin[4]] // zero value → sedan, RWD

	// Use touring chassis code when body code indicates estate.
	chassis = entry.chassis
	if bodyInfo.touring && entry.tourer != "" {
		chassis = entry.tourer
	}

	eng := bmwEngineCodes[vin[5]] // "" if unknown

	// Drivetrain string used for DB lookup.
	driveDB := "Rear-Wheel Drive"
	switch {
	case bodyInfo.xdrive:
		driveDB = "All Wheel-Drive"
	case entry.fwd:
		driveDB = "Front-Wheel Drive"
	}

	// Type-database lookup: try with engine suffix, then without.
	var dbMatch *VINVariant
	if eng != "" {
		dbMatch = lookupVariant(chassis, driveDB, eng)
	}
	if dbMatch == nil {
		dbMatch = lookupVariant(chassis, driveDB, "")
	}
	if dbMatch != nil {
		engine = dbMatch.Engine
		powerKW = dbMatch.PowerKW
		body = dbMatch.Body
		model = chassis + " " + dbMatch.Model
		return
	}

	// Fallback: build model string from hand-coded tables.
	var drive string
	if bodyInfo.xdrive {
		drive = "xDrive"
	}
	if len(entry.series) == 1 {
		model = chassis + " " + entry.series
		if eng != "" {
			model += eng
		}
	} else {
		model = chassis + " " + entry.series
		if eng != "" && eng != "M" {
			model += " " + eng
		}
	}
	if drive != "" {
		model += " " + drive
	}
	return
}

// diagadrToTarget converts the DIAGADR hex string from the ZGW response to the
// BMW ISTA target string.  The ZGW DIAGADR is half the numeric ISTA target ID,
// so we multiply by 2: DIAGADR "10" → 0x10×2 = 0x20 → "F020".
func diagadrToTarget(hexStr string) string {
	v, err := strconv.ParseInt(hexStr, 16, 64)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("F%03X", v*2)
}

// Info holds the result of a discovery step.
// VIN == "" means the 169.254 interface was found but ZGW has not responded yet.
type Info struct {
	IP      string // ZGW IP, e.g. "169.254.138.176"
	MAC     string // ZGW MAC, e.g. "48:C5:8D:90:51:5C"; empty until ZGW responds
	VIN     string // 17-char VIN; empty until ZGW responds
	Model   string // e.g. "G30 530i xDrive"; empty if not recognised
	Chassis string // e.g. "G30"; empty if not recognised
	Target  string // ISTA target, e.g. "F020"; from DIAGADR in ZGW response
	// From the embedded type database — empty/0 if car is not in DB:
	Engine  string // BMW engine code, e.g. "B57D30O0"
	PowerKW int    // engine output in kW, e.g. 195
	Body    string // body type, e.g. "Sedan", "Touring"
}

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

// doProbes sends the 4-byte ZGW discovery probe on all available 169.254
// interfaces (except skipName).  onPacket is called for every UDP packet
// received in response — both on the persistent rx socket (port 6811) and on
// the ephemeral per-interface sockets which stay open for probeRecvWindow.
func doProbes(rx *net.UDPConn, skipName string, onPacket func([]byte, *net.UDPAddr)) {
	// Both broadcast forms: limited (255.255.255.255) and directed link-local
	// subnet broadcast (169.254.255.255).  Some ZGW firmware only responds to
	// the directed form.
	bcastLimited  := &net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: zgwPort}
	bcastDirected := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: zgwPort}
	probe := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x11} // 0x0011 = 17 = VIN length, ZGW ignores probe without it

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

		// Keep the socket open for probeRecvWindow so the ZGW's unicast reply
		// (directed to this socket's ephemeral source port) is not lost.
		go func(conn *net.UDPConn) {
			defer conn.Close()
			buf := make([]byte, 4096)
			_ = conn.SetReadDeadline(time.Now().Add(probeRecvWindow))
			for {
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					return // deadline expired or closed
				}
				preview := n
				if preview > 32 {
					preview = 32
				}
				log.Printf("zgw: recv(ep) %d bytes from %s: % x", n, addr, buf[:preview])
				onPacket(buf[:n], addr)
			}
		}(sc)
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

	// processPacket parses a received UDP packet and updates state if it
	// contains a valid VIN.  Safe to call from multiple goroutines.
	processPacket := func(buf []byte, addr *net.UDPAddr) {
		m := vinRe.FindSubmatch(buf)
		if m == nil {
			log.Printf("zgw: no VIN in packet from %s", addr)
			return
		}
		vin := string(m[1])

		var target, mac string
		if dm := diagadrRe.FindSubmatch(buf); dm != nil {
			target = diagadrToTarget(string(dm[1]))
		}
		if mm := macRe.FindSubmatch(buf); mm != nil {
			mac = formatMAC(string(mm[1]))
		}
		chassis, model, engine, body, powerKW := decodeVIN(vin)

		log.Printf("zgw: ZGW at %s  VIN=%s  target=%s  model=%s", addr.IP, vin, target, model)
		mu.Lock()
		lastSeen = time.Now()
		mu.Unlock()
		notify(&Info{
			IP: addr.IP.String(), MAC: mac, VIN: vin,
			Model: model, Chassis: chassis, Target: target,
			Engine: engine, PowerKW: powerKW, Body: body,
		})
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

	// Receive loop on the persistent rx socket (port 6811).
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
			processPacket(buf[:n], addr)
		}
	}()

	// Periodic probe + interface re-scan.
	doProbes(rx, skipIfaceName, processPacket)

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Re-scan interfaces first so the UI is updated even without ZGW response.
			ifaceInfo := scanIfaces(skipIfaceName)

			doProbes(rx, skipIfaceName, processPacket)

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
	if _, err := conn.WriteToUDP([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x11}, broadcast); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		if m := vinRe.FindSubmatch(buf[:n]); m != nil {
			vin := string(m[1])
			var target, mac string
			if dm := diagadrRe.FindSubmatch(buf[:n]); dm != nil {
				target = diagadrToTarget(string(dm[1]))
			}
			if mm := macRe.FindSubmatch(buf[:n]); mm != nil {
				mac = formatMAC(string(mm[1]))
			}
			chassis, model, engine, body, powerKW := decodeVIN(vin)
			return &Info{
				IP: remoteAddr.IP.String(), MAC: mac, VIN: vin,
				Model: model, Chassis: chassis, Target: target,
				Engine: engine, PowerKW: powerKW, Body: body,
			}
		}
	}
}

// macRe extracts the raw 12-hex-char MAC from "BMWMAC<12hex>BMWVIN".
var macRe = regexp.MustCompile(`BMWMAC([0-9A-Fa-f]{12})`)

// formatMAC inserts colons into a raw 12-char hex string.
func formatMAC(s string) string {
	if len(s) != 12 {
		return s
	}
	return s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":" + s[6:8] + ":" + s[8:10] + ":" + s[10:12]
}

func equal(a, b *Info) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.IP == b.IP && a.VIN == b.VIN && a.Target == b.Target &&
		a.Model == b.Model && a.Engine == b.Engine && a.PowerKW == b.PowerKW
}

// FormatBMW returns the display string for the UI label.
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
	if info.PowerKW > 0 {
		s += fmt.Sprintf("  %dkW", info.PowerKW)
	}
	if info.Body != "" {
		s += "  " + info.Body
	}
	return s
}
