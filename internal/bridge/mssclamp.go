package bridge

import "encoding/binary"

// DefaultMSSClamp is the TCP MSS ceiling applied to bridged SYN segments.
//
// Rationale: a full 1514-byte inner Ethernet frame becomes, on the wire,
//   proto(15) + crypto(24 hdr + 16 tag) + frame + IP(20) + UDP(8)
// = frame + 83 bytes. At frame=1514 that is 1597 bytes > 1500 MTU, so every
// full-size data packet fragments — and a single lost fragment drops the whole
// datagram. Short request/response traffic (coding, Tool32) never hits this;
// sustained streams (ISTA reads, UDS ECU flashing over DoIP/ENET TCP) hit it on
// every packet and collapse. Clamping the inner TCP MSS keeps every segment
// small enough that the wrapped datagram fits a 1500 MTU with margin for
// slightly-reduced paths (PPPoE 1492, mobile, double-NAT) and the heavier
// Reality/TLS framing. 1300 costs ~4% throughput vs 1360 but never fragments.
const DefaultMSSClamp = 1300

// ClampTCPMSS lowers the TCP MSS option of an IPv4 TCP SYN frame to at most
// maxMSS, mutating frame in place and fixing the TCP checksum incrementally
// (RFC 1624). Frames that are not IPv4/TCP/SYN, carry no MSS option, or already
// advertise an MSS ≤ maxMSS are left untouched. maxMSS == 0 disables clamping.
//
// Copy-on-write: the input frame is NEVER mutated. When a SYN needs clamping (the
// rare case) a modified copy is returned; otherwise the original slice is returned
// unchanged. This matters on the receive path, where the caller may hand in a
// buffer still owned by the FEC decoder (retained for later loss recovery) —
// mutating it in place would corrupt a subsequently recovered frame in the same
// block. Callers must use the returned slice.
//
// This is the standard VPN "mssfix": the inner TCP endpoints negotiate a segment
// size that survives the VPN's per-frame overhead without IP fragmentation.
func ClampTCPMSS(frame []byte, maxMSS uint16) []byte {
	if maxMSS == 0 || len(frame) < 14 {
		return frame
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return frame // not IPv4
	}
	ip := frame[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return frame
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl || ip[9] != 6 { // protocol 6 = TCP
		return frame
	}
	tcp := ip[ihl:]
	if len(tcp) < 20 || tcp[13]&0x02 == 0 { // SYN flag
		return frame
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return frame
	}
	opts := tcp[20:dataOff]
	for i := 0; i+1 < len(opts); {
		switch opts[i] {
		case 0: // End of options
			return frame
		case 1: // NOP
			i++
			continue
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return frame
		}
		if opts[i] == 2 && optLen == 4 { // MSS option
			old := binary.BigEndian.Uint16(opts[i+2 : i+4])
			if old <= maxMSS {
				return frame // already small enough
			}
			// Absolute offsets so we can rewrite a fresh copy without re-parsing.
			mssAbs := 14 + ihl + 20 + i + 2 // MSS value within frame
			ckAbs := 14 + ihl + 16          // TCP checksum within frame
			out := make([]byte, len(frame))
			copy(out, frame)
			binary.BigEndian.PutUint16(out[mssAbs:mssAbs+2], maxMSS)
			fixChecksum16(out[ckAbs:ckAbs+2], old, maxMSS)
			return out
		}
		i += optLen
	}
	return frame
}

// fixChecksum16 applies the RFC 1624 incremental update for a single 16-bit
// field change (oldVal → newVal) to the checksum stored in ck[0:2].
func fixChecksum16(ck []byte, oldVal, newVal uint16) {
	hc := binary.BigEndian.Uint16(ck)
	sum := uint32(^hc) + uint32(^oldVal) + uint32(newVal)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ck, ^uint16(sum))
}
