// Package bmwbattery reads the 12 V battery state of a BMW (F-series and
// G-series/CLAR) over the ENET diagnostic link, with no external dependencies.
//
// It speaks the EDIABAS/AIFC TCP framing on port 6801 and queries the DME
// (ECU 0x12) with UDS ReadDataByIdentifier (service 0x22). The field mapping
// was reverse-engineered from traffic captures and confirmed against ISTA:
//
//	                     G-series (CLAR)            F-series
//	State of charge %  : DID 0x40AD byte[0]         DID 0x4023 byte[17]
//	Battery voltage  V : DID 0x40C3 (word in range) DID 0x4022 (best-effort)
//	Ageing / health  % : DID 0x40B5 byte[19]        — (not confirmed)
//
// Read dispatches by ISTA platform code (see IsGSeries / series.go).
//
// Quick start:
//
//	st, err := bmwbattery.Read("169.254.14.38", "S15A") // host, platform
//	if err == nil { fmt.Println(st) }                   // 🔋 62%  ·  V: 13.06  ·  Ageing 58%
//
// or poll continuously:
//
//	bmwbattery.Poll(ctx, host, platform, time.Minute, func(st *bmwbattery.Status, err error) { ... })
package bmwbattery

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Default ENET / diagnostic addressing.
const (
	Port       = 6801 // EDIABAS/AIFC TCP port on the ZGW
	testerAddr = 0xF4 // diagnostic tester source address
	dmeAddr    = 0x12 // DME / EDME target ECU
)

// Status is a single battery snapshot. The Has* flags report which fields were
// obtained — a given DID can fail independently (e.g. the DME answers SoC but
// not voltage), in which case that field is left zero with Has*==false.
type Status struct {
	SoCPercent    int     // state of charge, %
	HasSoC        bool    //
	VoltageV      float64 // battery voltage, volts
	HasVoltage    bool    //
	AgeingPercent int     // battery ageing / state of health, %
	HasAgeing     bool    //
}

// String renders the snapshot like "🔋 62%  ·  V: 13.06  ·  Ageing 58%".
// Missing fields are shown as a dash (voltage) or omitted (SoC/ageing).
func (s *Status) String() string {
	soc := "🔋 —"
	if s.HasSoC {
		soc = fmt.Sprintf("🔋 %d%%", s.SoCPercent)
	}
	volt := "V: —"
	if s.HasVoltage {
		volt = fmt.Sprintf("V: %.2f", s.VoltageV)
	}
	out := soc + "  ·  " + volt
	if s.HasAgeing {
		out += fmt.Sprintf("  ·  Ageing %d%%", s.AgeingPercent)
	}
	return out
}

// Read opens a fresh connection to the ZGW at host (its link-local 169.254.x.x
// IP, found via auto-search) and reads the battery, dispatching to the G- or
// F-series logic based on the ISTA platform code (see IsGSeries / series.go).
// Pass the platform from your discovery layer, e.g. zgw.Info.Platform —
// "S15A" (G), "F010" (F), …
//
// It returns whatever it managed to obtain; err is non-nil only when it can't
// connect or gets no response at all — a partial result (some fields missing)
// is returned with err == nil. G-series fills SoC + voltage + ageing; F-series
// fills SoC + best-effort voltage (no confirmed ageing field there yet).
func Read(host, platform string) (*Status, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, Port), 4*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", host, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		return nil, err
	}
	if IsGSeries(platform) {
		return readG(conn, host)
	}
	return readF(conn, host)
}

// readG reads a G-series (CLAR) battery: SoC 0x40AD[0], voltage 0x40C3, ageing 0x40B5[19].
func readG(conn net.Conn, host string) (*Status, error) {
	st := &Status{}
	got := false

	// SoC — DID 0x40AD, byte[0].
	if d, err := readDID(conn, 0x40, 0xAD); err == nil && len(d) > 0 {
		if v := d[0]; v >= 1 && v <= 100 {
			st.SoCPercent, st.HasSoC, got = int(v), true, true
		}
	}
	// Voltage — DID 0x40C3, first 16-bit word in battery range (BE then LE).
	if d, err := readDID(conn, 0x40, 0xC3); err == nil {
		if mv, ok := findVoltage(d); ok {
			st.VoltageV, st.HasVoltage, got = float64(mv)/1000.0, true, true
		}
	}
	// Ageing / SoH — DID 0x40B5, byte[19].
	if d, err := readDID(conn, 0x40, 0xB5); err == nil && len(d) > 19 {
		if v := d[19]; v >= 1 && v <= 100 {
			st.AgeingPercent, st.HasAgeing, got = int(v), true, true
		}
	}

	if !got {
		return st, fmt.Errorf("no battery data from %s (DME not responding?)", host)
	}
	return st, nil
}

// readF reads an F-series battery. SoC is the most-recent determined value —
// DID 0x4023 byte[17] ("Last" in ISTA's AS6120_SOC_HIST; 0xFF = no recent
// value). Voltage is best-effort from the 0x4022 sample ring.
func readF(conn net.Conn, host string) (*Status, error) {
	st := &Status{}
	got := false

	if d, err := readDID(conn, 0x40, 0x23); err == nil {
		got = true // DID answered (SoC may still be 0xFF "no recent value")
		if len(d) > 17 {
			if v := d[17]; v >= 1 && v <= 100 {
				st.SoCPercent, st.HasSoC = int(v), true
			}
		}
	}
	if d, err := readDID(conn, 0x40, 0x22); err == nil {
		if mv, ok := findVoltage(d); ok {
			st.VoltageV, st.HasVoltage, got = float64(mv)/1000.0, true, true
		}
	}

	if !got {
		return st, fmt.Errorf("no battery data from %s (DME not responding?)", host)
	}
	return st, nil
}

// findVoltage scans a data block for the first 16-bit word in a plausible 12 V
// battery range (11.0–15.2 V). These DIDs lay values out as aligned big-endian
// words, so try those first; misaligned/little-endian matches are a last resort
// to avoid false positives from straddling byte pairs.
func findVoltage(d []byte) (mv int, ok bool) {
	inRange := func(w int) bool { return w >= 11000 && w <= 15200 }
	for i := 0; i+1 < len(d); i += 2 { // aligned big-endian
		if w := int(d[i])<<8 | int(d[i+1]); inRange(w) {
			return w, true
		}
	}
	for i := 0; i+1 < len(d); i += 2 { // aligned little-endian
		if w := int(d[i+1])<<8 | int(d[i]); inRange(w) {
			return w, true
		}
	}
	for i := 0; i+1 < len(d); i++ { // any offset, either endianness
		if w := int(d[i])<<8 | int(d[i+1]); inRange(w) {
			return w, true
		}
		if w := int(d[i+1])<<8 | int(d[i]); inRange(w) {
			return w, true
		}
	}
	return 0, false
}

// ── EDIABAS / AIFC framing ─────────────────────────────────────────────────────
//
// Frame:  [4B payload length BE][2B type][payload]
// Type:   0x0001 = data, 0x0002 = ACK (echoes the request)
// UDS req:  [tester][ecu][0x22][DID hi][DID lo]
// UDS resp: [ecu][tester][0x62][DID hi][DID lo][data…]

// readDID sends UDS ReadDataByIdentifier 0x22 to the DME and returns the data
// bytes after the 0x62 echo.
func readDID(conn net.Conn, hi, lo byte) ([]byte, error) {
	if err := writeFrame(conn, []byte{testerAddr, dmeAddr, 0x22, hi, lo}); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		typ, payload, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		if typ != 0x0001 {
			continue // ACK echo — wait for the data frame
		}
		if len(payload) < 6 {
			return nil, fmt.Errorf("response too short")
		}
		if payload[2] == 0x7F {
			nrc := byte(0)
			if len(payload) > 4 {
				nrc = payload[4]
			}
			return nil, fmt.Errorf("UDS negative response (NRC=0x%02X)", nrc)
		}
		if payload[2] != 0x62 {
			return nil, fmt.Errorf("unexpected response 0x%02X", payload[2])
		}
		return payload[5:], nil
	}
	return nil, fmt.Errorf("no data frame")
}

func writeFrame(w io.Writer, payload []byte) error {
	buf := make([]byte, 6+len(payload))
	binary.BigEndian.PutUint32(buf[0:], uint32(len(payload)))
	binary.BigEndian.PutUint16(buf[4:], 0x0001) // data frame
	copy(buf[6:], payload)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) (msgType uint16, payload []byte, err error) {
	hdr := make([]byte, 6)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	msgType = binary.BigEndian.Uint16(hdr[4:6])
	if length > 0 {
		payload = make([]byte, length)
		_, err = io.ReadFull(r, payload)
	}
	return
}
