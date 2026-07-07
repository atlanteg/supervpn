package bridge

import (
	"encoding/binary"
	"testing"
)

// buildSYN builds a minimal Ethernet/IPv4/TCP SYN frame with one MSS option and
// a correct TCP checksum. Returns the frame and the offset of the TCP header.
func buildSYN(mss uint16) ([]byte, int) {
	eth := []byte{
		0x02, 0, 0, 0, 0, 0x02, // dst MAC
		0x02, 0, 0, 0, 0, 0x01, // src MAC
		0x08, 0x00, // IPv4
	}
	// IPv4 header (20 bytes), src 169.254.1.1 → dst 169.254.1.2
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	tcpLen := 24 // 20 header + 4 MSS option
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+tcpLen))
	ip[8] = 64  // TTL
	ip[9] = 6   // TCP
	copy(ip[12:16], []byte{169, 254, 1, 1})
	copy(ip[16:20], []byte{169, 254, 1, 2})

	tcp := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcp[0:2], 12345)  // src port
	binary.BigEndian.PutUint16(tcp[2:4], 6801)   // dst port
	tcp[12] = 6 << 4                             // data offset 6 words = 24 bytes
	tcp[13] = 0x02                               // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	// MSS option
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	setTCPChecksum(ip, tcp)

	frame := append(append(eth, ip...), tcp...)
	return frame, len(eth) + 20
}

// tcpChecksum computes the TCP checksum over the pseudo-header + tcp bytes.
func tcpChecksum(ip, tcp []byte) uint16 {
	var sum uint32
	sum += uint32(ip[12])<<8 | uint32(ip[13]) // src hi/lo
	sum += uint32(ip[14])<<8 | uint32(ip[15])
	sum += uint32(ip[16])<<8 | uint32(ip[17]) // dst hi/lo
	sum += uint32(ip[18])<<8 | uint32(ip[19])
	sum += uint32(6)              // protocol
	sum += uint32(len(tcp))       // TCP length
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func setTCPChecksum(ip, tcp []byte) {
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(ip, tcp))
}

func TestClampTCPMSS_LowersAndKeepsChecksumValid(t *testing.T) {
	frame, tcpOff := buildSYN(1460)
	ClampTCPMSS(frame, 1300)

	got := binary.BigEndian.Uint16(frame[tcpOff+22 : tcpOff+24])
	if got != 1300 {
		t.Fatalf("MSS not clamped: got %d, want 1300", got)
	}
	// Verify the checksum still validates against a full recompute.
	ip := frame[14:34]
	tcp := frame[tcpOff:]
	stored := binary.BigEndian.Uint16(tcp[16:18])
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	want := tcpChecksum(ip, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], stored)
	if stored != want {
		t.Fatalf("checksum invalid after clamp: stored=%#04x want=%#04x", stored, want)
	}
}

func TestClampTCPMSS_NoChangeWhenAlreadySmall(t *testing.T) {
	frame, tcpOff := buildSYN(1200)
	before := make([]byte, len(frame))
	copy(before, frame)
	ClampTCPMSS(frame, 1300)
	if binary.BigEndian.Uint16(frame[tcpOff+22:tcpOff+24]) != 1200 {
		t.Fatal("MSS 1200 should be left untouched (already ≤ 1300)")
	}
}

func TestClampTCPMSS_IgnoresNonSYN(t *testing.T) {
	frame, tcpOff := buildSYN(1460)
	tcp := frame[tcpOff:]
	tcp[13] = 0x10 // ACK only, no SYN
	setTCPChecksum(frame[14:34], tcp)
	ClampTCPMSS(frame, 1300)
	if binary.BigEndian.Uint16(frame[tcpOff+22:tcpOff+24]) != 1460 {
		t.Fatal("non-SYN frame must not be clamped")
	}
}

func TestClampTCPMSS_IgnoresNonTCPAndShort(t *testing.T) {
	// ARP frame (ethertype 0x0806) must be left alone.
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	cp := make([]byte, len(arp))
	copy(cp, arp)
	ClampTCPMSS(arp, 1300)
	for i := range arp {
		if arp[i] != cp[i] {
			t.Fatal("ARP frame mutated")
		}
	}
	// Runt frames must not panic.
	ClampTCPMSS([]byte{1, 2, 3}, 1300)
	ClampTCPMSS(nil, 1300)
}

func TestClampTCPMSS_Disabled(t *testing.T) {
	frame, tcpOff := buildSYN(1460)
	ClampTCPMSS(frame, 0) // disabled
	if binary.BigEndian.Uint16(frame[tcpOff+22:tcpOff+24]) != 1460 {
		t.Fatal("maxMSS=0 must disable clamping")
	}
}
