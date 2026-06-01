//go:build darwin

// macOS TUN integration via Apple's native utun kernel control.
//
// macOS does not have a kernel TAP (L2) device; utun provides L3 (IP).
// Each packet read from or written to utun is prefixed with a 4-byte
// address-family header: [0x00, 0x00, 0x00, AF] where AF is AF_INET (2)
// or AF_INET6 (30). We strip this header on read and prepend it on write.
//
// Because the supervpn hub is an L2 switch (Ethernet frames), the darwinL2
// wrapper performs L2 emulation:
//   - Assigns a random virtual MAC to this utun session.
//   - Wraps outgoing IP packets in Ethernet frames (src=virtual MAC).
//   - Answers ARP requests for our IP with our virtual MAC.
//   - Strips Ethernet headers from incoming frames before writing to utun.
//   - Caches remote IP→MAC mappings from ARP replies/traffic for unicast.
package tun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/atlanteg/supervpn/internal/bridge"
	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"
	utunOptIfname   = 2 // UTUN_OPT_IFNAME getsockopt option
	sysprotoControl = 2 // SYSPROTO_CONTROL — not exported by golang.org/x/sys/unix
)

type darwinTUN struct {
	fd int
}

// openPlatform creates a new utun device.  ifaceName is ignored — macOS
// assigns the device name automatically (utun0, utun1, …).
func openPlatform(_ string) (*darwinL2, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("tun/darwin: socket: %w", err)
	}

	var ctlInfo unix.CtlInfo
	copy(ctlInfo.Name[:], utunControlName)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.CTLIOCGINFO, uintptr(unsafe.Pointer(&ctlInfo)))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun/darwin: CTLIOCGINFO: %w", errno)
	}

	if err := unix.Connect(fd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: 0,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun/darwin: connect utun: %w", err)
	}

	raw := &darwinTUN{fd: fd}
	return newDarwinL2(raw), nil
}

func (t *darwinTUN) readIP(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		var rfds unix.FdSet
		rfds.Bits[t.fd/32] |= int32(1) << uint(t.fd%32)
		tv := unix.Timeval{Sec: 0, Usec: 100_000}
		_, err := unix.Select(t.fd+1, &rfds, nil, nil, &tv)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tun/darwin: select: %w", err)
		}
		if rfds.Bits[t.fd/32]&(int32(1)<<uint(t.fd%32)) == 0 {
			continue
		}
		n, err := unix.Read(t.fd, buf)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tun/darwin: read: %w", err)
		}
		if n < 4 {
			continue
		}
		pkt := make([]byte, n-4)
		copy(pkt, buf[4:n])
		return pkt, nil
	}
}

func (t *darwinTUN) writeIP(ip []byte) error {
	if len(ip) == 0 {
		return nil
	}
	buf := make([]byte, 4+len(ip))
	if len(ip) > 0 && ip[0]>>4 == 6 {
		buf[3] = unix.AF_INET6
	} else {
		buf[3] = unix.AF_INET
	}
	copy(buf[4:], ip)
	_, err := unix.Write(t.fd, buf)
	return err
}

func (t *darwinTUN) Close() error { return unix.Close(t.fd) }

func (t *darwinTUN) IfName() string {
	var name [unix.IFNAMSIZ + 1]byte
	nameLen := uintptr(len(name))
	unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(t.fd), sysprotoControl, utunOptIfname,
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)), 0)
	if nameLen > 1 {
		return string(name[:nameLen-1])
	}
	return "utun"
}

// ── L2 emulation ─────────────────────────────────────────────────────────────

var (
	etherBroadcast = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

// darwinL2 wraps darwinTUN and presents a full Ethernet (L2) interface to the
// rest of the client, matching what Windows TAP and bridge clients send/receive.
type darwinL2 struct {
	tun    *darwinTUN
	mac    [6]byte    // our virtual MAC (randomly generated)
	myIP   [4]byte    // set from NIC config or learned from first outgoing IPv4 packet
	arp    sync.Map   // [4]byte IP → [6]byte MAC
	inject chan []byte // frames to return from ReadFrame (ARP replies)
}

func newDarwinL2(t *darwinTUN) *darwinL2 {
	var mac [6]byte
	rand.Read(mac[:])
	mac[0] = (mac[0] &^ 0x01) | 0x02 // locally administered, unicast
	d := &darwinL2{tun: t, mac: mac, inject: make(chan []byte, 16)}
	// Pre-populate myIP from the utun interface so ARP requests from remote
	// machines are answered immediately, without waiting for the first outgoing
	// packet (which may never come if the remote machine initiates contact first).
	d.myIP = ifaceIP(t.IfName())
	return d
}

// ifaceIP returns the first IPv4 address configured on ifaceName, or zero.
func ifaceIP(ifaceName string) [4]byte {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return [4]byte{}
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return [4]byte{}
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP.To4()
		case *net.IPAddr:
			ip = v.IP.To4()
		}
		if ip != nil {
			var out [4]byte
			copy(out[:], ip)
			return out
		}
	}
	return [4]byte{}
}

// ReadFrame returns an Ethernet frame to send to the hub.
// ARP replies injected by WriteFrame are returned first.
func (d *darwinL2) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case f := <-d.inject:
		return f, nil
	default:
	}

	ip, err := d.tun.readIP(ctx)
	if err != nil {
		return nil, err
	}

	// Learn our own IP from the first outgoing IPv4 packet.
	if ip[0]>>4 == 4 && len(ip) >= 20 {
		var src [4]byte
		copy(src[:], ip[12:16])
		if d.myIP == ([4]byte{}) {
			d.myIP = src
		}
	}

	// Pick destination MAC: unicast if we know it, broadcast otherwise.
	dst := etherBroadcast
	if ip[0]>>4 == 4 && len(ip) >= 20 {
		var dstIP [4]byte
		copy(dstIP[:], ip[16:20])
		if v, ok := d.arp.Load(dstIP); ok {
			dst = v.([6]byte)
		}
	}

	frame := make([]byte, 14+len(ip))
	copy(frame[0:6], dst[:])
	copy(frame[6:12], d.mac[:])
	if ip[0]>>4 == 6 {
		frame[12], frame[13] = 0x86, 0xDD
	} else {
		frame[12], frame[13] = 0x08, 0x00
	}
	copy(frame[14:], ip)
	return frame, nil
}

// WriteFrame processes an incoming Ethernet frame from the hub.
func (d *darwinL2) WriteFrame(frame []byte) error {
	if len(frame) < 14 {
		return nil
	}
	dstMAC := [6]byte{}
	copy(dstMAC[:], frame[0:6])
	srcMAC := [6]byte{}
	copy(srcMAC[:], frame[6:12])

	// Drop frames not addressed to us (unless broadcast/multicast).
	if dstMAC != d.mac && dstMAC != etherBroadcast && dstMAC[0]&0x01 == 0 {
		return nil
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[14:]

	switch etherType {
	case 0x0800: // IPv4
		if len(payload) < 20 {
			return nil
		}
		// Learn source IP→MAC mapping.
		var srcIP [4]byte
		copy(srcIP[:], payload[12:16])
		if srcMAC != etherBroadcast {
			d.arp.Store(srcIP, srcMAC)
		}
		return d.tun.writeIP(payload)

	case 0x86DD: // IPv6
		return d.tun.writeIP(payload)

	case 0x0806: // ARP
		d.handleARP(payload, srcMAC)
	}
	return nil
}

func (d *darwinL2) handleARP(payload []byte, srcMAC [6]byte) {
	// ARP packet: HTYPE(2) PTYPE(2) HLEN(1) PLEN(1) OPER(2) SHA(6) SPA(4) THA(6) TPA(4)
	if len(payload) < 28 {
		return
	}
	oper := binary.BigEndian.Uint16(payload[6:8])
	var sha [6]byte
	copy(sha[:], payload[8:14])
	var spa, tpa [4]byte
	copy(spa[:], payload[14:18])
	copy(tpa[:], payload[24:28])

	// Learn sender.
	if sha != etherBroadcast && spa != ([4]byte{}) {
		d.arp.Store(spa, sha)
	}

	if oper == 1 && tpa == d.myIP && d.myIP != ([4]byte{}) {
		// ARP request for our IP — send reply.
		reply := buildARPReply(d.mac, d.myIP, sha, spa)
		eth := make([]byte, 14+len(reply))
		copy(eth[0:6], sha[:])    // dst = requester
		copy(eth[6:12], d.mac[:]) // src = us
		eth[12], eth[13] = 0x08, 0x06
		copy(eth[14:], reply)
		select {
		case d.inject <- eth:
		default:
		}
	}
}

func buildARPReply(ourMAC [6]byte, ourIP [4]byte, dstMAC [6]byte, dstIP [4]byte) []byte {
	p := make([]byte, 28)
	binary.BigEndian.PutUint16(p[0:2], 1)    // HTYPE Ethernet
	binary.BigEndian.PutUint16(p[2:4], 0x0800) // PTYPE IPv4
	p[4] = 6                                  // HLEN
	p[5] = 4                                  // PLEN
	binary.BigEndian.PutUint16(p[6:8], 2)    // OPER reply
	copy(p[8:14], ourMAC[:])
	copy(p[14:18], ourIP[:])
	copy(p[18:24], dstMAC[:])
	copy(p[24:28], dstIP[:])
	return p
}

func (d *darwinL2) Close() error  { return d.tun.Close() }
func (d *darwinL2) IfName() string { return d.tun.IfName() }

var _ bridge.Framer = (*darwinL2)(nil)
