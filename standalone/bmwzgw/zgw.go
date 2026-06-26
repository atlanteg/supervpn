// Package bmwzgw implements BMW ZGW (Central Gateway) discovery over the
// ENET link-local network and full VIN-to-chassis decoding.
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
//     again with the real ZGW IP, VIN, decoded model info, and ISTA platform.
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
//	    // "BMW: 169.254.138.176  WBA5R7C0XLFH66853  G20 330i xDrive  S18A"
//	})
//
// # VIN decoding — cascade (most precise → fallback)
//
// BMW uses a 4-character internal type key (Baumuster, VIN[3:7]).
//
//  0. faTypeKeys — checked first.  Exact VIN[3:7] lookup, learned from real BMW
//     FA backups (~725 keys, ~99% chassis-accurate).  Returns chassis + model
//     (e.g. "330i") + xDrive.  e.g. "5R7C" → G20 330i xDrive.
//
//  1. bmwType2Keys — VIN[3]+VIN[4], for keys not in faTypeKeys.  90+ entries;
//     covers overloaded VIN[3] letters, e.g. '5'+'R' → G20.
//
//  2. gseriesIntroMY + fseriesAltKeys — VIN[9] (ISO model-year char; VIN[8] is
//     the check digit) disambiguates VIN[3] letters reused across F/G gens:
//     'H' threshold 'K' (2019): before → F48 X1 FWD; after → G29 Z4
//     'K' threshold 'G' (2016): before → F15 X5;    after → G11/G12
//     'W' threshold 'N' (2022): before → F25 X3;    after → G26 4GC
//
//  3. bmwTypeKeys — single-character VIN[3] fallback (most-common model).
//
// Platform: platformForChassis() prefers the FA-learned faChassisPlatform
// (real I-Step data) over the hand-curated chassisPlatform.
//
// # FA XML training data
//
// The lookup tables were built from BMW ISTA Fahrzeugauftrag (FA) XML files
// collected from real-car diagnostic backups.  An FA XML is the authoritative
// vehicle order document stored in the VCM MASTER backup folder; it contains
// the exact chassis series code (e.g. "G020") and the full 4-char type key
// (e.g. "5R7C").  Accuracy history:
//
//	v1.5.6 (73 FA XMLs):   ~48%  bmwTypeKeys only
//	v1.5.7 (73 FA XMLs):   ~65%  + initial bmwType2Keys (4 entries)
//	v1.6.0 (7546 FA XMLs): ~89%  + 90+ bmwType2Keys entries
//
// To contribute a new mapping: open the FA.xml from a VCM MASTER backup,
// read vinLong / series / typeKey, and add an entry to bmwType2Keys keyed
// by [2]byte{typeKey[0], typeKey[1]}.  Also add the chassis to chassisPlatform
// if missing.
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

// bmwModelEntry maps a BMW type key to its chassis platform codes and series name.
// chassis is the base/sedan body; tourer is the estate/wagon variant (empty if N/A).
type bmwModelEntry struct {
	chassis string // base chassis code, e.g. "G20" (sedan/coupé/standard body)
	tourer  string // touring/estate variant chassis, e.g. "G21"; "" = not applicable
	series  string // series label: single digit "3" or named "X5", "M3"
	fwd     bool   // true = front-wheel drive platform (F45, F46, F48, F39, F40, …)
}

// bmwBodyInfo describes the body style and drivetrain encoded in VIN[4].
type bmwBodyInfo struct {
	touring bool // estate/wagon (Touring) body — selects the entry.tourer chassis code
	xdrive  bool // BMW xDrive all-wheel drive
}

// bmwBodyCodes maps VIN[4] to body style and drivetrain.
// Only non-default (sedan/RWD) combinations are listed;
// any code absent from this map → standard sedan/coupé body, rear-wheel drive.
var bmwBodyCodes = map[byte]bmwBodyInfo{
	// AWD, standard body
	'X': {false, true}, // xDrive sedan (all series, all generations)
	'W': {false, true}, // xDrive SAC/SAV body (X4 F26 and similar non-DE plants)
	// G20/G22 xDrive: these VIN[4] values encode xDrive for G-series 3/4-series.
	// Confirmed: WBA5R7C0XLFH66853 (G20 330i xDrive, typeKey 5R7C),
	//            WBA5V780608B86343 (G20 320d xDrive, typeKey 5V78),
	//            WBA3V9C56FP946935 (F33 428i xDrive, typeKey 3V93).
	'R': {false, true}, // xDrive (G20/G22 G-series)
	'V': {false, true}, // xDrive (G20/G22 G-series, also F33 cabriolet)
	// F-series Touring
	'B': {true, false}, // F31 / F11 Touring, RWD
	'D': {true, true},  // F31 / F11 Touring, xDrive
	'K': {true, false}, // F31 Touring, RWD (confirmed: typeKey 8K12 = F031)
	// G-series Touring, RWD
	'E': {true, false}, // G21 / G31 / G61 Touring, RWD
	// G-series Touring, xDrive
	'N': {true, true}, // G21 / G31 Touring, xDrive
	// M Touring
	'F': {true, false}, // G81 M3 Touring, RWD
	'G': {true, true},  // G81 M3 Touring, xDrive (Competition xDrive)
}

// chassisPlatform maps chassis code (as returned by decodeVIN) to the BMW ISTA
// software platform identifier.  Used to display the diagnostic platform name
// instead of the raw DIAGADR-derived target address.
//
// Sources: ISTA VehicleInfo → Series mappings (bimmer-tool DB, screenshots).
// Platform families:
//
//	F001  — 7 Series F01/F02/F04 (2008–2015)
//	F010  — 5 Series F07/F10/F11, 6 Series F12/F13 (2010–2017)
//	F020  — 1/2/3/4 Series F20–F36, M3 F80, M4 F82/F83 (2011–2019)
//	F025  — X3 F25, X4 F26, X5 F15/F85, X6 F16/F86 (2011–2019)
//	F056  — UKL FWD: 1-Series F40, X1 F48, X2 F39, 2AT F45/F46 (2014–2022)
//	S15A  — CLAR gen 1: 5 Series G30/G31/G32, 7 Series G11/G12, X3 G01/F97, X4 G02/F98, M5 F90
//	S18A  — CLAR gen 2: 3/4 Series G20–G26, 8 Series G14–G16,
//	         X5 G05, X6 G06, X7 G07, Z4 G29, 2 Series G42, M2–M4/M3
//	G045  — Electric: iX G045/G046/G048
//	G070  — New gen: 5 Series G60, 7 Series G70, M5 G84/G90
var chassisPlatform = map[string]string{
	// ── F-series ──────────────────────────────────────────────────────────────
	// platform F001: 7 Series F01/F02/F04
	"F01": "F001", "F02": "F001", "F04": "F001",
	// platform F010: 5 Series F07/F10/F11, 6 Series F12/F13
	"F07": "F010",
	"F10": "F010", "F11": "F010", "F12": "F010", "F13": "F010",
	// platform F025: X5 F15/F85, X6 F16/F86, X3 F25, X4 F26
	"F15": "F025", "F16": "F025", "F25": "F025", "F26": "F025",
	"F85": "F025", "F86": "F025",
	// platform F020: 1/2/3/4 Series mainstream + M3/M4 F-gen
	"F20": "F020", "F21": "F020",
	"F22": "F020", "F23": "F020",
	"F30": "F020", "F31": "F020", "F32": "F020", "F33": "F020",
	"F34": "F020", "F35": "F020", "F36": "F020",
	"F40": "F020",                               // 1-Series G-gen / F40 (UKL2-based)
	"F44": "F020",                               // 2 Series Gran Coupé F44
	"F52": "F020",                               // 1 Series F52 (China)
	"F80": "F020", "F82": "F020", "F83": "F020", // M3/M4 F-gen (F30/F32 platform)
	// platform F056: UKL FWD — X1 F48, X2 F39, 2 Active/Gran Tourer F45/F46
	"F39": "F056", "F45": "F056", "F46": "F056",
	"F47": "F056", "F48": "F056", "F49": "F056",
	// ── G-series — CLAR gen 1 (S15A) ─────────────────────────────────────────
	// 5 Series G30/G31/G32, 7 Series G11/G12, X3 G01/F97, X4 G02/F98, M5 F90
	"F90": "S15A", "F97": "S15A", "F98": "S15A",
	"G01": "S15A", "G02": "S15A",
	"G11": "S15A", "G12": "S15A",
	"G30": "S15A", "G31": "S15A", "G32": "S15A",
	// ── G-series — CLAR gen 1 extended (S15C) ────────────────────────────────
	// 5 Series long-wheelbase G38, X3M G08 (China/specific markets)
	"G08": "S15C", "G38": "S15C",
	// ── G-series — CLAR gen 2 (S18A) ─────────────────────────────────────────
	// 3 Series G20/G21, 4 Series G22/G23/G26, 2 Series G42
	"G20": "S18A", "G21": "S18A", "G28": "S18A",
	"G22": "S18A", "G23": "S18A", "G24": "S18A", "G26": "S18A",
	"G42": "S18A",
	// X3M G09, X5 G05, X6 G06, X7 G07
	"G05": "S18A", "G06": "S18A", "G07": "S18A", "G09": "S18A",
	// 8 Series G14/G15/G16, Z4 G29
	"G14": "S18A", "G15": "S18A", "G16": "S18A",
	"G29": "S18A",
	// M2 G87, M3 G80/G81, M4 G82/G83
	"G80": "S18A", "G81": "S18A",
	"G82": "S18A", "G83": "S18A",
	"G87": "S18A",
	// ── G-series — new generation electric (G045) ─────────────────────────────
	// iX G045/G046/G048
	"G45": "G045", "G46": "G045", "G48": "G045",
	// ── G-series — new generation ICE (G070) ──────────────────────────────────
	// 5 Series G60/G61, 7 Series G70/G71, M5 G84/G90/G99
	"G60": "G070", "G61": "G070",
	"G68": "G070", "G70": "G070", "G71": "G070",
	"G72": "G070", "G73": "G070",
	"G84": "G070", "G90": "G070", "G99": "G070",
}

// VIN[10] model-year character encoding (I / O / Q are omitted):
//
//	A=2010 B=2011 C=2012 D=2013 E=2014 F=2015 G=2016
//	H=2017 J=2018 K=2019 L=2020 M=2021 N=2022 P=2023 R=2024
//
// BMW reuses VIN[3] type-key letters across generations.  The two tables below
// handle disambiguation:
//
//	gseriesIntroMY  — maps a type-key letter to the VIN[10] character at which
//	                  G-series production for that key began.  Only populated
//	                  for keys that were provably used for a different F-series
//	                  model before the G-series took over.
//
//	fseriesAltKeys  — the F-series meaning of those reused keys.
//
// When VIN[10] < gseriesIntroMY[key], decodeVIN uses fseriesAltKeys instead
// of bmwTypeKeys.  Keys with no confirmed F-series predecessor are left out of
// both tables so they fall through to bmwTypeKeys unmodified.
// gseriesIntroMY maps a type-key byte to the VIN[10] character at which
// G-series production for that key began.  Cars whose VIN[10] < threshold
// are decoded via fseriesAltKeys instead of bmwTypeKeys.
//
// Thresholds verified against real FA XML backups (73 cars, 2026).
var gseriesIntroMY = map[byte]byte{
	// 'H': G29 Z4 from MY2019 ('K'); before that it was the X1 F48 (FWD).
	//      F48 VINs show vin[10]='5' (digit, 2015-2016 prod); G29 shows 'W' (2021).
	//      Note: China long-wheelbase X1 F49 (vin[10]='M') is also pre-G29 era
	//      but shares the key — it will be misidentified as G29 on this branch;
	//      acceptable given F49 is a China-only variant.
	'H': 'K',
	// 'K': G11 7-series from MY2016 ('G'); before that it was F15 X5 / F16 X6 / F85 X5M.
	//      F-series K VINs show vin[10]='0' (digit) or 'C'; G11 shows 'G'.
	//      One G11 anomaly: WBA7C21070BP41411 has vin[10]='B' (< 'G') — accepted.
	'K': 'G',
	// 'W': G26 4-series Gran Coupé from MY2022 ('N'); before that it was the X3 F25.
	//      F25 VINs show vin[10]='L' or digit '0'; G26 starts at 'N' range.
	'W': 'N',
}

var fseriesAltKeys = map[byte]bmwModelEntry{
	// X1 F48 (predecessor of G29 Z4 on key 'H'). FWD platform.
	'H': {"F48", "", "X1", true},
	// X5 F15 (most common predecessor of G11 on key 'K').
	// F16 X6, F85 X5M, F02 750Li also used 'K'; best-guess default is F15.
	'K': {"F15", "", "X5", false},
	// X3 F25 (predecessor of G26 4GC on key 'W').
	'W': {"F25", "", "X3", false},
}

// bmwType2Keys maps the first TWO characters of the BMW type key (VIN[3]+VIN[4])
// to chassis data.  Checked before the single-character bmwTypeKeys table, so
// entries here take priority and override the generic single-character fallback.
//
// Used for heavily overloaded VIN[3] letters where a single character is not
// enough to distinguish the model.  All entries verified against real BMW ISTA
// FA XML backups (7 546 files, 2026).  Count = number of FA XML occurrences.
//
// IMPORTANT: entries with tourer=="" force a specific chassis regardless of the
// global bmwBodyCodes table, because body-code semantics differ per model family.
// For example VIN[4]='D' means "xDrive sedan" for G30 but "xDrive Touring" for F31.
var bmwType2Keys = map[[2]byte]bmwModelEntry{
	// ── VIN[3]='1' — 1/5-series overload ────────────────────────────────────
	{'1', '1'}: {"G30", "", "5", false}, // G30 5-series (typeKey 11BH/11DC/11DW, 42 VINs)
	{'1', '3'}: {"G30", "", "5", false}, // G30 5-series (18 VINs)
	{'1', 'J'}: {"F22", "", "2", false}, // F22 2-series coupé (10 VINs)

	// ── VIN[3]='2' — 2/7-series overload ────────────────────────────────────
	{'2', '1'}: {"G07", "", "X7", false}, // G07 X7 (typeKey 21EM/21EN, 38 VINs)
	{'2', '3'}: {"G07", "", "X7", false}, // G07 X7 (typeKey 23EM, 22 VINs)
	{'2', 'J'}: {"F22", "", "2", false},  // F22 2-series coupé (14 VINs)
	{'2', 'M'}: {"F23", "", "2", false},  // F23 2-series cabriolet (8 VINs)

	// ── VIN[3]='3' — 3/4-series F-gen + G-series overload ───────────────────
	// F30 sedan: body codes A/B/C/D are drive variants in this family, NOT Touring.
	// Using explicit chassis (tourer="") to bypass global bmwBodyCodes misread.
	{'3', 'A'}: {"F30", "", "3", false}, // F30 sedan RWD (typeKey 3A11/3A51, 64 VINs)
	{'3', 'B'}: {"F30", "", "3", false}, // F30 sedan (typeKey 3B11/3B13, 71 VINs)
	{'3', 'C'}: {"F30", "", "3", false}, // F30 sedan (typeKey 3C17/3C31, 21 VINs)
	{'3', 'D'}: {"F30", "", "3", false}, // F30 sedan xDrive (typeKey 3D11/3D31, 54 VINs)
	// F31 Touring (explicit)
	{'3', 'K'}: {"F31", "", "3", false}, // F31 Touring RWD (typeKey 3K11/3K31, 30 VINs)
	{'3', 'L'}: {"F31", "", "3", false}, // F31 Touring (typeKey 3L11/3L51, 16 VINs)
	// F33 4-series Cabriolet (confirmed: WBA3V9C56FP946935, typeKey 3V93)
	{'3', 'V'}: {"F33", "", "4", false}, // F33 4-series Convertible (6 VINs)
	// F34 3-series Gran Turismo
	{'3', 'X'}: {"F34", "", "3", false}, // F34 GT (typeKey 3X11/3X31, 29 VINs)
	{'3', 'Y'}: {"F34", "", "3", false}, // F34 GT xDrive (typeKey 3Y11/3Y31, 29 VINs)
	{'3', 'Z'}: {"F34", "", "3", false}, // F34 GT (typeKey 3Z71, 6 VINs)
	// F82/F83 M4
	{'3', 'R'}: {"F82", "", "M4", false}, // F82 M4 coupé (typeKey 3R91/3R93, 6 VINs)
	{'3', 'U'}: {"F83", "", "M4", false}, // F83 M4 cabriolet (typeKey 3U93, 6 VINs)

	// ── VIN[3]='4' — 4-series / M3 overload ─────────────────────────────────
	{'4', '1'}: {"G80", "", "M3", false}, // G80 M3 (typeKey 41AY/WBS, 16 VINs)
	{'4', '3'}: {"G80", "", "M3", false}, // G80 M3 Competition (typeKey 43AY, 30 VINs)
	{'4', 'W'}: {"F32", "", "4", false},  // F32 4-series coupé xDrive (typeKey 4W11, 19 VINs)
	{'4', 'Z'}: {"F33", "", "4", false},  // F33 4-series cabriolet (typeKey 4Z11, 10 VINs)

	// ── VIN[3]='5' — 5-series/3-series/X3 overload ──────────────────────────
	// G20/G21 3-series G-gen — confirmed: WBA5R7C0XLFH66853 (330i xDrive, typeKey 5R7C)
	{'5', 'F'}: {"G20", "G21", "3", false}, // G20 sedan (typeKey 5F7x, 17 VINs)
	{'5', 'P'}: {"G20", "G21", "3", false}, // G20 sedan (typeKey 5P7x, 20 VINs)
	{'5', 'R'}: {"G20", "G21", "3", false}, // G20 sedan xDrive (typeKey 5R7x, confirmed)
	{'5', 'U'}: {"G20", "G21", "3", false}, // G20 sedan (typeKey 5U7x, 60 VINs)
	{'5', 'V'}: {"G20", "G21", "3", false}, // G20 sedan xDrive (typeKey 5V7x, confirmed)
	{'5', 'W'}: {"G20", "G21", "3", false}, // G20 sedan (typeKey 5W7x, 4 VINs)
	{'5', 'X'}: {"G20", "G21", "3", false}, // G20 sedan xDrive (typeKey 5X7x, 12 VINs)
	// G22/G23 4-series — confirmed: WBA53AP00PCN03414 (430i, typeKey 53AP)
	{'5', '3'}: {"G22", "G23", "4", false}, // G22/G23 4-series (typeKey 53Ax)
	// G01 X3 BMW SA Rosslyn — confirmed: WBX57DP06NN153154 (typeKey 57DP)
	{'5', '7'}: {"G01", "", "X3", false}, // G01 X3 (BMW SA Rosslyn)
	// F10/F11 5-series body-code fix (B/D/E treated as Touring → wrong)
	{'5', 'B'}: {"F10", "", "5", false}, // F10 sedan (typeKey 5B11, 14 VINs)
	{'5', 'D'}: {"F10", "", "5", false}, // F10 sedan xDrive (typeKey 5D11, 11 VINs)
	{'5', 'E'}: {"F10", "", "5", false}, // F10 sedan (typeKey 5E11, 14 VINs)
	// F11 Touring (explicit, body code 'L'/'J' not in bmwBodyCodes)
	{'5', 'J'}: {"F11", "", "5", false}, // F11 Touring (typeKey 5J51, 8 VINs)
	{'5', 'L'}: {"F11", "", "5", false}, // F11 Touring (typeKey 5L51, 16 VINs)
	// F07 5GT
	{'5', 'N'}: {"F07", "", "5", false}, // F07 5GT (typeKey 5N61, 2 VINs)

	// ── VIN[3]='6' — 6-series / 3-series / 2-series overload ────────────────
	// G20/G21 3-series on '6' typekey
	{'6', '8'}: {"G20", "", "3", false}, // G20 3-series (typeKey 68xx, 8 VINs)
	{'6', '9'}: {"G20", "", "3", false}, // G20 3-series (4 VINs)
	{'6', 'L'}: {"G21", "", "3", false}, // G21 Touring (typeKey 6L31/6L71, 32 VINs)
	{'6', 'M'}: {"G21", "", "3", false}, // G21 Touring (8 VINs)
	{'6', 'N'}: {"G21", "", "3", false}, // G21 Touring (6 VINs)
	// F45/F46 2-series AT/GT FWD on '6' typekey
	{'6', 'S'}: {"F45", "", "2", true}, // F45 2AT FWD (4 VINs)
	{'6', 'T'}: {"F45", "", "2", true}, // F45 2AT FWD (4 VINs)
	{'6', 'U'}: {"F45", "", "2", true}, // F45 2AT FWD (4 VINs)
	{'6', 'X'}: {"F46", "", "2", true}, // F46 2GT FWD (8 VINs)
	{'6', 'Y'}: {"F45", "", "2", true}, // F45 2AT FWD (4 VINs)

	// ── VIN[3]='7' — 7-series / F40 1-series / G30 5-series overload ────────
	// G12 LWB (these VIN[4] values encode LWB but not in global bmwBodyCodes)
	{'7', 'H'}: {"G12", "", "7", false}, // G12 LWB (typeKey 7H61, 2 VINs)
	{'7', 'J'}: {"G12", "", "7", false}, // G12 LWB (typeKey 7J23, 4 VINs)
	{'7', 'T'}: {"G12", "", "7", false}, // G12 LWB (typeKey 7T23, 16 VINs)
	{'7', 'U'}: {"G12", "", "7", false}, // G12 LWB (typeKey 7U23/7U61, 32 VINs)
	{'7', 'V'}: {"G12", "", "7", false}, // G12 LWB (typeKey 7V61, 4 VINs)
	// G11 SWB — bypass body 'B'=Touring misread (tourer="" → stays G11)
	{'7', 'B'}: {"G11", "", "7", false}, // G11 SWB (typeKey 7B61, 6 VINs)
	// F40 1-series G-gen (UKL2 FWD platform reusing '7' typekey)
	{'7', 'K'}: {"F40", "", "1", true}, // F40 1-series (typeKey 7K31/7K51, 24 VINs)
	{'7', 'L'}: {"F40", "", "1", true}, // F40 1-series (typeKey 7L11, 6 VINs)
	{'7', 'M'}: {"F40", "", "1", true}, // F40 1-series (typeKey 7M91, 4 VINs)
	{'7', 'N'}: {"F40", "", "1", true}, // F40 1-series Touring (typeKey 7N51, 8 VINs)
	// G30/G20 reusing '7' typekey
	{'7', '1'}: {"G30", "", "5", false}, // G30 5-series (typeKey 71BH/71BJ/71DC, 32 VINs)
	{'7', '3'}: {"G30", "", "5", false}, // G30 5-series (typeKey 73BJ, 10 VINs)
	{'7', '8'}: {"G20", "", "3", false}, // G20 3-series (typeKey 78DY, 10 VINs)

	// ── VIN[3]='8' — 3-series F-gen variants ────────────────────────────────
	// F34 Gran Turismo body: VIN[4]='T','X','Y','Z' encodes GT body
	{'8', 'T'}: {"F34", "", "3", false}, // F34 GT RWD (typeKey 8T11/8T31, 42 VINs)
	{'8', 'X'}: {"F34", "", "3", false}, // F34 GT xDrive (typeKey 8X11/8X51, 34 VINs)
	{'8', 'Y'}: {"F34", "", "3", false}, // F34 GT (typeKey 8Y11, 12 VINs)
	{'8', 'Z'}: {"F34", "", "3", false}, // F34 GT (typeKey 8Z71, 4 VINs)
	// F31 Touring — body codes J/H not in global bmwBodyCodes
	{'8', 'H'}: {"F31", "", "3", false}, // F31 Touring (typeKey 8H31, 4 VINs)
	{'8', 'J'}: {"F31", "", "3", false}, // F31 Touring (typeKey 8J31, 18 VINs)
	// F80 M3 (high-performance F30 variant)
	{'8', 'M'}: {"F80", "", "M3", false}, // F80 M3 (typeKey 8M01/8M02, 8 VINs)

	// ── VIN[3]='B' — 6/8-series overload ────────────────────────────────────
	{'B', 'C'}: {"G15", "", "8", false}, // G15 8-series coupé (typeKey BC21/BC41, 52 VINs)

	// ── VIN[3]='C' — X5/X6/X7 disambiguation ────────────────────────────────
	// G05 X5 on CV/CR is already correct (default 'C'→G05)
	{'C', 'W'}: {"G07", "", "X7", false}, // G07 X7 (typeKey CW21/CW81, 228 VINs — biggest fix)
	{'C', 'X'}: {"G07", "", "X7", false}, // G07 X7 xDrive (typeKey CX61, 8 VINs)
	{'C', 'Y'}: {"G06", "", "X6", false}, // G06 X6 (typeKey CY61/CY81, 68 VINs)

	// ── VIN[3]='F' — X1 F48 vs F10 5-series BMW SA disambiguation ───────────
	// BMW SA (WMI X4X/WBAFW) uses 'F' typekey prefix for F10 5-series
	{'F', 'P'}: {"F10", "F11", "5", false}, // F10/F11 BMW SA (typeKey FP15/FP31, 26 VINs)
	{'F', 'R'}: {"F10", "F11", "5", false}, // F10/F11 BMW SA (typeKey FR11/FR73, 10 VINs)
	{'F', 'U'}: {"F10", "F11", "5", false}, // F10/F11 BMW SA (typeKey FU71/FU91, 14 VINs)
	{'F', 'V'}: {"F10", "F11", "5", false}, // F10/F11 BMW SA (typeKey FV15, 9 VINs)
	{'F', 'W'}: {"F10", "F11", "5", false}, // F10/F11 BMW SA (typeKey FW11/FW31, 31 VINs)

	// ── VIN[3]='G' — X2 F39 vs X6 G06 vs 8-series G16 disambiguation ────────
	{'G', 'T'}: {"G06", "", "X6", false}, // G06 X6 (typeKey GT21/GT61/GT81, 108 VINs)
	{'G', 'V'}: {"G16", "", "8", false},  // G16 8-series GC (typeKey GV41/GV43, 22 VINs)
	{'G', 'W'}: {"G16", "", "8", false},  // G16 8-series GC xDrive (typeKey GW41, 20 VINs)

	// ── VIN[3]='H' — Z4 G29 vs X1 F48 (precise, overrides gseriesIntroMY) ───
	// Confirmed: WBAHF51090WX29248 (G29 Z4 M40i, typeKey HF51)
	{'H', 'F'}: {"G29", "", "Z4", false}, // G29 Z4 (typeKey HF51, confirmed)
	// Confirmed: WBAHS120205F03712 (F48 X1 sDrive18i, typeKey HS12)
	{'H', 'S'}: {"F48", "", "X1", true}, // F48 X1 FWD (typeKey HS12/HS13, confirmed)
	{'H', 'Y'}: {"F48", "", "X1", true}, // F48 X1 FWD (typeKey HY31/HY51, 8 VINs)

	// ── VIN[3]='J' — G30/G31/G32/G05/F48 disambiguation ────────────────────
	// G30 sedan: VIN[4] is drive/engine variant, NOT body style in G-gen.
	// Using tourer="" so body codes B/D/E/F/K are ignored (they'd wrongly give G31).
	{'J', 'B'}: {"G30", "", "5", false}, // G30 sedan (typeKey JB13/JB31/JB91, 77 VINs)
	{'J', 'D'}: {"G30", "", "5", false}, // G30 sedan xDrive (typeKey JD11/JD51, 191 VINs)
	{'J', 'E'}: {"G30", "", "5", false}, // G30 sedan (typeKey JE31/JE53, 84 VINs)
	{'J', 'F'}: {"G30", "", "5", false}, // G30 sedan (typeKey JF31/JF51, 142 VINs)
	{'J', 'K'}: {"G30", "", "5", false}, // G30 sedan (typeKey JK51, 4 VINs)
	// G31 Touring (explicit)
	{'J', 'L'}: {"G31", "", "5", false}, // G31 Touring (typeKey JL51, 4 VINs)
	{'J', 'M'}: {"G31", "", "5", false}, // G31 Touring (typeKey JM31/JM51, 12 VINs)
	{'J', 'P'}: {"G31", "", "5", false}, // G31 Touring (typeKey JP11/JP31/JP51, 26 VINs)
	// G32 6-series Gran Turismo
	{'J', 'V'}: {"G32", "", "6", false}, // G32 6GT (typeKey JV11/JV31, 14 VINs)
	{'J', 'W'}: {"G32", "", "6", false}, // G32 6GT xDrive (typeKey JW11/JW31, 20 VINs)
	{'J', 'X'}: {"G32", "", "6", false}, // G32 6GT (typeKey JX31, 12 VINs)
	// G05 X5 (reuses J typekey family)
	{'J', 'U'}: {"G05", "", "X5", false}, // G05 X5 (typeKey JU23/JU43/JU81, 38 VINs)
	// F48 X1 (reuses J typekey family)
	{'J', 'G'}: {"F48", "", "X1", true}, // F48 X1 FWD (typeKey JG12/JG51, 34 VINs)
	{'J', 'H'}: {"F48", "", "X1", true}, // F48 X1 FWD (typeKey JH31, 10 VINs)
	{'J', 'J'}: {"F48", "", "X1", true}, // F48 X1 FWD (typeKey JJ51, 8 VINs)

	// ── VIN[3]='K' — F-series overload (gseriesIntroMY catches G11, but not all F variants) ─
	// F02 7-series LWB
	{'K', 'B'}: {"F02", "", "7", false}, // F02 750Li xDrive (typeKey KB21/KB81, 24 VINs)
	{'K', 'C'}: {"F01", "", "7", false}, // F01 7-series (typeKey KC01/KC61, 21 VINs)
	{'K', 'M'}: {"F01", "", "7", false}, // F01 7-series (typeKey KM21, 20 VINs)
	// G01 X3 (TX/KJ prefix = Texas or European G01)
	{'K', 'J'}: {"G01", "", "X3", false}, // G01 X3 (typeKey KJ31/KJ71 ≈ TX, 36 VINs)
	// F10/F11 5-series reusing 'K' key
	{'K', 'N'}: {"F10", "F11", "5", false}, // F10 5-series (typeKey KN93, 4 VINs)
	{'K', 'P'}: {"F10", "F11", "5", false}, // F10 5-series (typeKey KP91, 4 VINs)
	// F15 X5 post-G11-intro (vin[10]>='G' but still F15 for these VIN[4] values)
	{'K', 'R'}: {"F15", "", "X5", false}, // F15 X5 (typeKey KR01/KR03, 20 VINs)
	// F85/F86 X5M/X6M
	{'K', 'T'}: {"F85", "", "X5", false}, // F85 X5M (typeKey KT61, 24 VINs)
	{'K', 'U'}: {"F16", "", "X6", false}, // F16 X6 (typeKey KU03/KU21, 26 VINs)
	{'K', 'V'}: {"F16", "", "X6", false}, // F16 X6 (typeKey KV21/KV61, 58 VINs)
	{'K', 'W'}: {"F86", "", "X6", false}, // F86 X6M (typeKey KW61, 14 VINs)

	// ── VIN[3]='L' — F15 X5 BMW SA (additional to default F13) ─────────────
	{'L', 'S'}: {"F15", "", "X5", false}, // F15 X5 BMW SA (typeKey LS01/LS61, 19 VINs)

	// ── VIN[3]='M' — F11 5-series Touring (override G02 default) ───────────
	{'M', 'X'}: {"F11", "", "5", false}, // F11 Touring (typeKey MX51/MX71, 31 VINs)

	// ── VIN[3]='S' — F07 5GT (override G29 Z4 default) ─────────────────────
	{'S', 'N'}: {"F07", "", "5", false}, // F07 5-series GT (typeKey SN61, 4 VINs)
	{'S', 'P'}: {"F07", "", "5", false}, // F07 5-series GT (typeKey SP21/SP61/SP81, 27 VINs)

	// ── VIN[3]='T' — X3/X5/X6/X7/M car disambiguation ──────────────────────
	// Default 'T'→G01 X3 is correct for TS31/TX71/TY53/TZ31 typekeys.
	// But some 'T' typekeys encode different G-series models:
	{'T', 'A'}: {"G05", "", "X5", false}, // G05 X5 (typeKey TA61, 14 VINs)
	{'T', 'B'}: {"G07", "", "X7", false}, // G07 X7 (typeKey TB31, 4 VINs)
	{'T', 'C'}: {"G06", "", "X6", false}, // G06 X6 (typeKey TC21/TC61, 8 VINs)
	// NOTE: {'T','S'} removed — TS31/TX71 typekeys are G01 X3 M40i (Sport, not M-car),
	// while TS01/TS03 are F97 X3M; cannot disambiguate without WMI (WBA vs WBS).

	// ── VIN[3]='U' — F98 X4M (override G01 X3 default) ─────────────────────
	{'U', 'J'}: {"F98", "", "X4", false}, // F98 X4M (typeKey UJ01/UJ03, 12 VINs)

	// ── VIN[3]='V' — G02 X4 (override G82 M4 default) ──────────────────────
	{'V', 'J'}: {"G02", "", "X4", false}, // G02 X4 (typeKey VJ11/VJ31/VJ51, 38 VINs)

	// ── VIN[3]='X' — BMW SA 5-series (override F26 X4 default) ─────────────
	// WMI X4X/WBAFX = BMW SA 5-series F10 using 'X' typekey prefix
	{'X', 'A'}: {"F10", "F11", "5", false}, // F10/F11 BMW SA (typeKey XA11/XA31, 16 VINs)
	{'X', 'G'}: {"F10", "F11", "5", false}, // F10/F11 BMW SA (typeKey XG75, confirmed F010)
	{'X', 'H'}: {"F10", "F11", "5", false}, // F10/F11 BMW SA (typeKey XH15, confirmed F010)

	// ── VIN[3]='Y' — F01/F02/F12/F13 overload (overrides F39 X2 default) ───
	{'Y', 'B'}: {"F01", "", "7", false}, // F01 7-series (typeKey YB21/YB41, 16 VINs)
	{'Y', 'C'}: {"F01", "", "7", false}, // F01 7-series (typeKey YC41, 21 VINs)
	{'Y', 'E'}: {"F02", "", "7", false}, // F02 7-series LWB (typeKey YE41, 2 VINs)
	{'Y', 'F'}: {"F02", "", "7", false}, // F02 7-series LWB (typeKey YF41, 8 VINs)
	{'Y', 'M'}: {"F13", "", "6", false}, // F13 6-series coupé (typeKey YM11/YM61, 10 VINs)
	{'Y', 'P'}: {"F12", "", "6", false}, // F12 6-series cabriolet (typeKey YP11/YP61, 8 VINs)
}

// bmwTypeKeys maps VIN[3] (BMW Baumuster / type key) to chassis + series.
//
// Entries verified against real FA XML vehicle backups (73 cars, 2026).
// BMW reuses type-key letters across generations; see gseriesIntroMY /
// fseriesAltKeys above for generation disambiguation.
//
// WARNING: BMW uses a 4-char internal type key (VIN[3:7]); we decode only
// VIN[3] here, so some models sharing the same first character can't be
// distinguished without also inspecting VIN[4] and/or the WMI (VIN[0:3]).
// The entry for each ambiguous key is the most-common European model.
// Use bmwType2Keys above for cases where VIN[3]+VIN[4] is needed.
var bmwTypeKeys = map[byte]bmwModelEntry{
	// ── E-series ──────────────────────────────────────────────────────────────
	'9': {"E90", "E91", "3", false}, // 3 Series E90 sedan / E91 Touring

	// ── F-series (confirmed from FA XML) ─────────────────────────────────────
	// '1' is heavily reused: F20 (1-series), later G30 (5-series), G08 (X3 China),
	// F44 (2GC) — default to F20 as the most common European case.
	'1': {"F20", "F21", "1", false}, // 1 Series F20/F21 (also G30/G08/F44 — see note)
	// '2' is reused: F45/F46 FWD, F52/F98 China, G02/G20/G32 — default F45 FWD.
	'2': {"F45", "F46", "2", true}, // 2 Active/Gran Tourer F45/F46 (FWD; also G02/G20 — see note)
	// '3': dominant use is F30/F31/F34 3-series.  F33 4-series Cabriolet also uses
	// '3' but is handled via bmwType2Keys['3','V'].  Rare VIN[4] values not in
	// type2Keys fall back here (e.g. '3N'/'3P' → F32 coupé — close enough, same platform).
	'3': {"F30", "F31", "3", false}, // 3 Series F30 sedan / F31 Touring (default)
	// '4' confirmed = F36 4-series Gran Coupé (typeKey 4F11, series F036).
	// F32 coupé and F33 cabriolet handled via bmwType2Keys entries.
	'4': {"F36", "", "4", false}, // 4 Series Gran Coupé F36 (default)
	// '5' is reused: F10/F11 (Germany), F07 5GT, G01/G20/G22 (various plants).
	// Default to F10/F11 as the most common European case.
	'5': {"F10", "F11", "5", false}, // 5 Series F10 sedan / F11 Touring (also G01/G20/G22)
	'6': {"F12", "", "6", false},    // 6 Series F12 cabrio / F06 Gran Coupé
	// '7' confirmed = G11/G12 7-series G-gen (typeKey 7C21/7C41, series G011).
	// F01/F02 7-series F-gen use 'K' (not '7') per FA XML data.
	'7': {"G11", "G12", "7", false}, // 7 Series G11 SWB / G12 LWB
	// '8' confirmed = F30 sedan, F31 Touring (typeKey 8A51/8K12/8E36, series F030/F031).
	// F34 GT also uses '8' with VIN[4]='T'; default to F30 sedan (most common).
	'8': {"F30", "F31", "3", false}, // 3 Series F30 sedan / F31 Touring (also F34 GT)
	'A': {"F15", "", "X5", false},   // X5 F15
	'B': {"F16", "", "X6", false},   // X6 F16
	// 'C' confirmed = G05/G06 (typeKey CV61/CY81, series G005/G006).
	// F25 X3 uses 'W', not 'C' per FA XML data.
	'C': {"G05", "", "X5", false}, // X5 G05 (also G06 X6 — see VIN[4])
	'D': {"F26", "", "X4", false}, // X4 F26 (German plant)
	'E': {"F45", "", "2", true},   // 2 Series Active Tourer F45 (FWD, secondary key)
	'F': {"F48", "", "X1", true},  // X1 F48 (FWD) — BMW SA also uses 'F' for F10 5-series
	'G': {"F39", "", "X2", true},  // X2 F39 (FWD)

	// ── G-series ─────────────────────────────────────────────────────────────
	// 'H' confirmed = G29 Z4 (typeKey HF51, series G029).
	// F48 X1 also uses 'H'; disambiguated via gseriesIntroMY['H']='K'.
	'H': {"G29", "", "Z4", false},   // Z4 G29 (before MY2019: X1 F48 FWD via fseriesAltKeys)
	'J': {"G30", "G31", "5", false}, // 5 Series G30 sedan / G31 Touring (also F90 M5)
	// 'K' confirmed = G11 for MY>=2016; F15/F16/F85 for earlier MY (via gseriesIntroMY).
	'K': {"G11", "G12", "7", false}, // 7 Series G11/G12 (before MY2016: X5 F15 via fseriesAltKeys)
	// 'L' confirmed = F13 6-series (typeKey LX51, series F013) and F15 X5 (typeKey LS01).
	// G01 X3 uses 'T'/'U'/'5' in FA XML data — NOT 'L'.
	'L': {"F13", "", "6", false},  // 6 Series Coupé F13 (also F15 X5 on same key)
	'M': {"G02", "", "X4", false}, // X4 G02 (unverified — no G02 with 'M' in test set)
	'N': {"G05", "", "X5", false}, // X5 G05 (unverified secondary key)
	'P': {"G06", "", "X6", false}, // X6 G06 (unverified secondary key)
	'R': {"G07", "", "X7", false}, // X7 G07 (unverified)
	'S': {"G29", "", "Z4", false}, // Z4 G29 (unverified secondary key)
	// 'T' confirmed = G01 X3 (typeKey TS31/TX71/TY53, series G001).
	// G05 X5 also uses 'T' (typeKey TA61); differentiated by VIN[4]='A'→G05.
	'T': {"G01", "", "X3", false}, // X3 G01 (also G05 X5 with VIN[4]='A')
	// 'U' confirmed = G01 X3 (typeKey UZ31, series G001).
	'U': {"G01", "", "X3", false},    // X3 G01 (alternative type key)
	'V': {"G82", "G83", "M4", false}, // M4 G82 coupé / G83 cabrio (unverified)
	// 'W' confirmed = F25 X3 (typeKey WX71/WX39/WZ59, series F025).
	// G26 4GC is the G-series successor; disambiguated via gseriesIntroMY['W']='N'.
	'W': {"G26", "", "4", false}, // 4 Series Gran Coupé G26 (before MY2022: X3 F25 via fseriesAltKeys)
	// 'X' confirmed = F26 X4 (BMW SA, WMI X4X) and F10 5-series (BMW SA).
	// German G22 4-series uses VIN[3]='5' per FA XML — NOT 'X'.
	'X': {"F26", "", "X4", false}, // X4 F26 (BMW SA plant; also F10 5-series on same key)
	// 'Y' confirmed = F39 X2 FWD (typeKey YH12, series F039).
	// G15 8-series uses a different type key per FA XML data.
	'Y': {"F39", "", "X2", true}, // X2 F39 (FWD)
	'Z': {"G16", "", "8", false}, // 8 Series Gran Coupé G16 (unverified)
}

// bmwEngineCodes maps VIN[5] to the engine/displacement suffix appended to the model name.
// This is a shared best-effort table for F- and G-series; some codes differ between
// generations, and rare/market-specific variants may not be listed.
var bmwEngineCodes = map[byte]string{
	'0': "16i",
	'1': "18i", '2': "20d", '3': "30d", '4': "35i",
	'5': "20i", '6': "40i", '7': "35d", '8': "40d",
	'9': "50i",
	'A': "16d", 'B': "18d", 'C': "20d", 'D': "25d",
	'E': "30i", 'F': "M", 'G': "M", 'H': "25e",
	'J': "30e", 'K': "45e", 'L': "25i", 'N': "28i",
	'P': "35i", 'R': "28d", 'S': "M", 'T': "30i",
	'U': "30i", 'V': "40i", 'W': "50e", 'X': "45e",
	'Y': "M", 'Z': "60i",
}

// decodeVIN returns the chassis code, human-readable model label, and — when
// a match is found in the embedded type database — the BMW engine code, body
// type, and power output.  Returns empty strings for unrecognised type keys.
//
// VIN positions used (0-indexed):
//
//	[3] type key (BMW Baumuster) → chassis platform
//	[4] body style / drivetrain  → sedan vs Touring, RWD vs xDrive
//	[5] engine code              → displacement/fuel suffix
//
// Examples:
//
//	"WBA8X51000CF40263" → chassis "F34", model "F34 320i xDrive"
//	"WBA3B51090F123456" → chassis "F31", model "F31 320i"   (Touring)
//	"WBAHE510X0H12345"  → chassis "G20", model "G20 318i xDrive"
//	"WBAHE5100EH12345"  → chassis "G21", model "G21 318i"   (Touring)
//
// platformForChassis returns the ISTA platform for a chassis, preferring the
// FA-learned map (real I-Step data) over the hand-curated chassisPlatform.
func platformForChassis(chassis string) string {
	if p, ok := faChassisPlatform[chassis]; ok {
		return p
	}
	return chassisPlatform[chassis]
}

func decodeVIN(vin string) (chassis, model, engine, body string, powerKW int) {
	if len(vin) < 17 {
		return
	}

	// Step 0: FA-learned exact 4-char type-key lookup (VIN[3:7]) — authoritative
	// for the ~725 type keys seen in real BMW FA backups (~99% chassis accuracy).
	// Falls through to the heuristic steps below for unknown keys.
	if fa, ok := faTypeKeys[vin[3:7]]; ok {
		chassis = fa.chassis
		model = fa.chassis
		if fa.model != "" {
			model += " " + fa.model
		}
		drive := "Rear-Wheel Drive"
		if fa.xdrive {
			model += " xDrive"
			drive = "All Wheel-Drive"
		}
		if dm := lookupVariant(chassis, drive, ""); dm != nil {
			engine = dm.Engine
			powerKW = dm.PowerKW
			body = dm.Body
		}
		return
	}

	// Resolve type key — accounting for BMW reusing the same VIN[3] letter
	// across generations.  VIN[9] is the ISO 3779 model-year character (VIN[8]
	// is the check digit) and lets us determine which generation the car
	// belongs to.
	typeKey := vin[3]
	myChar := vin[9]
	var entry bmwModelEntry
	var ok bool

	// Step 1: try the two-character lookup (VIN[3]+VIN[4]) first.
	// This overrides the single-character table for heavily overloaded keys
	// (e.g. '5' is shared by F10 5-series AND G20/G22/G01).
	if entry, ok = bmwType2Keys[[2]byte{vin[3], vin[4]}]; !ok {
		// Step 2: single-character lookup with generation disambiguation.
		if introMY, reused := gseriesIntroMY[typeKey]; reused && myChar < introMY {
			// VIN predates G-series introduction for this key → use F-series entry.
			entry, ok = fseriesAltKeys[typeKey]
		} else {
			entry, ok = bmwTypeKeys[typeKey]
		}
	}
	if !ok {
		return
	}

	bodyInfo := bmwBodyCodes[vin[4]] // zero value → sedan, RWD

	// Refine chassis: use touring variant when the body code indicates an estate.
	chassis = entry.chassis
	if bodyInfo.touring && entry.tourer != "" {
		chassis = entry.tourer
	}

	eng := bmwEngineCodes[vin[5]] // "" if unknown

	// Determine drivetrain string for DB lookup.
	driveDB := "Rear-Wheel Drive"
	switch {
	case bodyInfo.xdrive:
		driveDB = "All Wheel-Drive"
	case entry.fwd:
		driveDB = "Front-Wheel Drive"
	}

	// ── Type-database lookup ─────────────────────────────────────────────────
	// Try with the exact engine suffix first; if nothing matches (e.g. suffix
	// is wrong for the platform), retry without the suffix constraint.
	var dbMatch *VINVariant
	if eng != "" {
		dbMatch = lookupVariant(chassis, driveDB, eng)
	}
	if dbMatch == nil {
		dbMatch = lookupVariant(chassis, driveDB, "") // drivetrain-only match
	}

	if dbMatch != nil {
		// DB found a match: use its model name, engine code, power and body.
		engine = dbMatch.Engine
		powerKW = dbMatch.PowerKW
		body = dbMatch.Body
		model = chassis + " " + dbMatch.Model
		return
	}

	// ── Fallback: build model string from our hand-coded tables ─────────────
	var drive string
	if bodyInfo.xdrive {
		drive = "xDrive"
	}

	if len(entry.series) == 1 {
		// Single-digit series: chassis + " " + series + eng → "G20 318i"
		model = chassis + " " + entry.series
		if eng != "" {
			model += eng
		}
	} else {
		// Named model (X1–X7, Z4, M3, M4, 8 Series…): space-separated.
		// M3/M4: engine tag is already "M" — same as the series name, skip it.
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
	IP       string // ZGW or interface IP, e.g. "169.254.138.176"
	MAC      string // ZGW MAC address, e.g. "48:C5:8D:90:51:5C"; empty until ZGW responds
	VIN      string // 17-char VIN, e.g. "WBA8X51000CF40263"; empty until ZGW responds
	Model    string // decoded model label, e.g. "G30 530i xDrive"; empty if not recognised
	Chassis  string // chassis code, e.g. "G30"; empty if not recognised
	Target   string // ISTA ECU target address, e.g. "F020" (from DIAGADR×2); empty if absent
	Platform string // ISTA software platform, e.g. "S15A", "S18A", "F020"; empty if unknown
	// Fields below are populated only when a match is found in the type database:
	Engine  string // BMW engine code, e.g. "B57D30O0"; empty if not in DB
	PowerKW int    // engine output in kW, e.g. 195; 0 if not in DB
	Body    string // body type, e.g. "Sedan", "Touring"; empty if not in DB
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
		var engine, body string
		var powerKW int
		chassis, model, engine, body, powerKW = decodeVIN(vin)
		platform := platformForChassis(chassis)

		log.Printf("bmwzgw: ZGW at %s  VIN=%s  target=%s  platform=%s  model=%s", addr.IP, vin, target, platform, model)
		mu.Lock()
		lastSeen = time.Now()
		mu.Unlock()
		notify(&Info{
			IP:       addr.IP.String(),
			MAC:      mac,
			VIN:      vin,
			Model:    model,
			Chassis:  chassis,
			Target:   target,
			Platform: platform,
			Engine:   engine,
			PowerKW:  powerKW,
			Body:     body,
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
		var engine, body string
		var powerKW int
		chassis, model, engine, body, powerKW = decodeVIN(vin)
		return &Info{
			IP:       remoteAddr.IP.String(),
			MAC:      mac,
			VIN:      vin,
			Model:    model,
			Chassis:  chassis,
			Target:   target,
			Platform: platformForChassis(chassis),
			Engine:   engine,
			PowerKW:  powerKW,
			Body:     body,
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
	bcastLimited := &net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: zgwPort}
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
	return a.IP == b.IP && a.VIN == b.VIN && a.Target == b.Target && a.Model == b.Model && a.Platform == b.Platform
}
