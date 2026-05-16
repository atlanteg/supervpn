//go:build windows

// WinTun L2 emulation — wraps the L3 WinTun device with a virtual Ethernet
// layer so Windows direct-mode clients can participate in the hub's L2 domain.
//
// WinTun uses kernel ring buffers and is not subject to the NDIS Lightweight
// Filter (LWF) driver chain, so FortiClient and similar security software
// cannot intercept or drop its I/O — unlike tap-windows6 WriteFile which goes
// through the full NDIS stack.
//
// L2 emulation strategy (mirrors darwinL2 on macOS):
//   - A random locally-administered unicast MAC is assigned per session.
//   - Outgoing IP packets are wrapped in Ethernet frames (src = virtual MAC).
//   - Incoming Ethernet frames are unwrapped; their IP payload is injected into WinTun.
//   - ARP requests for our IP are answered via the inject channel.
//   - Remote IP→MAC mappings are learned from ARP replies and IPv4 traffic.
package tun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/atlanteg/supervpn/internal/bridge"
)

var winEtherBroadcast = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type windowsTUNL2 struct {
	tun    *windowsTUN
	mac    [6]byte  // virtual MAC for this session
	myIP   [4]byte  // learned from first outgoing IPv4 packet
	arp    sync.Map // string([4]byte) → [6]byte MAC
	inject chan []byte
}

// OpenWinTunL2 creates a WinTun adapter with the given name and wraps it in
// full Ethernet L2 emulation, returning a bridge.Framer ready for hub use.
func OpenWinTunL2(name string) (bridge.Framer, error) {
	raw, err := openWinTUN(name)
	if err != nil {
		return nil, err
	}
	return newWindowsTUNL2(raw), nil
}

func newWindowsTUNL2(t *windowsTUN) *windowsTUNL2 {
	var mac [6]byte
	rand.Read(mac[:])
	mac[0] = (mac[0] &^ 0x01) | 0x02 // locally administered, unicast
	return &windowsTUNL2{tun: t, mac: mac, inject: make(chan []byte, 16)}
}

// ReadFrame returns an Ethernet frame destined for the hub.
// Injected ARP replies are returned ahead of WinTun IP packets.
func (d *windowsTUNL2) ReadFrame(ctx context.Context) ([]byte, error) {
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
	if len(ip) >= 20 && ip[0]>>4 == 4 {
		var src [4]byte
		copy(src[:], ip[12:16])
		if d.myIP == ([4]byte{}) {
			d.myIP = src
		}
	}

	// Pick destination MAC: unicast if we know the mapping, broadcast otherwise.
	dst := winEtherBroadcast
	if len(ip) >= 20 && ip[0]>>4 == 4 {
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
func (d *windowsTUNL2) WriteFrame(frame []byte) error {
	if len(frame) < 14 {
		return nil
	}
	var dstMAC [6]byte
	copy(dstMAC[:], frame[0:6])
	var srcMAC [6]byte
	copy(srcMAC[:], frame[6:12])

	// Drop unicast frames not addressed to us.
	if dstMAC != d.mac && dstMAC != winEtherBroadcast && dstMAC[0]&0x01 == 0 {
		return nil
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[14:]

	switch etherType {
	case 0x0800: // IPv4
		if len(payload) < 20 {
			return nil
		}
		var srcIP [4]byte
		copy(srcIP[:], payload[12:16])
		if srcMAC != winEtherBroadcast {
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

func (d *windowsTUNL2) handleARP(payload []byte, srcMAC [6]byte) {
	if len(payload) < 28 {
		return
	}
	oper := binary.BigEndian.Uint16(payload[6:8])
	var sha [6]byte
	copy(sha[:], payload[8:14])
	var spa, tpa [4]byte
	copy(spa[:], payload[14:18])
	copy(tpa[:], payload[24:28])

	if sha != winEtherBroadcast && spa != ([4]byte{}) {
		d.arp.Store(spa, sha)
	}

	if oper == 1 && tpa == d.myIP && d.myIP != ([4]byte{}) {
		reply := buildWinARPReply(d.mac, d.myIP, sha, spa)
		eth := make([]byte, 14+len(reply))
		copy(eth[0:6], sha[:])
		copy(eth[6:12], d.mac[:])
		eth[12], eth[13] = 0x08, 0x06
		copy(eth[14:], reply)
		select {
		case d.inject <- eth:
		default:
		}
	}
}

func buildWinARPReply(ourMAC [6]byte, ourIP [4]byte, dstMAC [6]byte, dstIP [4]byte) []byte {
	p := make([]byte, 28)
	binary.BigEndian.PutUint16(p[0:2], 1)      // HTYPE Ethernet
	binary.BigEndian.PutUint16(p[2:4], 0x0800) // PTYPE IPv4
	p[4] = 6
	p[5] = 4
	binary.BigEndian.PutUint16(p[6:8], 2) // OPER reply
	copy(p[8:14], ourMAC[:])
	copy(p[14:18], ourIP[:])
	copy(p[18:24], dstMAC[:])
	copy(p[24:28], dstIP[:])
	return p
}

func (d *windowsTUNL2) Close() error   { return d.tun.Close() }
func (d *windowsTUNL2) IfName() string { return d.tun.IfName() }

var _ bridge.Framer = (*windowsTUNL2)(nil)
