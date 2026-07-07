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
// This is the standard VPN "mssfix": the inner TCP endpoints negotiate a segment
// size that survives the VPN's per-frame overhead without IP fragmentation.
func ClampTCPMSS(frame []byte, maxMSS uint16) {
	if maxMSS == 0 || len(frame) < 14 {
		return
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return // not IPv4
	}
	ip := frame[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl || ip[9] != 6 { // protocol 6 = TCP
		return
	}
	tcp := ip[ihl:]
	if len(tcp) < 20 || tcp[13]&0x02 == 0 { // SYN flag
		return
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return
	}
	opts := tcp[20:dataOff]
	for i := 0; i+1 < len(opts); {
		switch opts[i] {
		case 0: // End of options
			return
		case 1: // NOP
			i++
			continue
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return
		}
		if opts[i] == 2 && optLen == 4 { // MSS option
			old := binary.BigEndian.Uint16(opts[i+2 : i+4])
			if old > maxMSS {
				binary.BigEndian.PutUint16(opts[i+2:i+4], maxMSS)
				fixTCPChecksum16(tcp, old, maxMSS)
			}
			return
		}
		i += optLen
	}
}

// fixTCPChecksum16 applies the RFC 1624 incremental update for a single 16-bit
// field change (oldVal → newVal) to the TCP checksum at tcp[16:18].
func fixTCPChecksum16(tcp []byte, oldVal, newVal uint16) {
	hc := binary.BigEndian.Uint16(tcp[16:18])
	sum := uint32(^hc) + uint32(^oldVal) + uint32(newVal)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))
}
