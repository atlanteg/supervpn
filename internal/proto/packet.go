// Package proto defines the wire format for supervpn packets.
//
// Frame layout (UDP payload):
//
//	[frame_type: 1][hub_id: 2][session_id: 4][seq: 8][payload...]
//
// For FEC repair frames, payload contains the repair block header + repair symbols.
package proto

import "encoding/binary"

type FrameType uint8

const (
	FrameData   FrameType = 0x01 // encrypted L2 Ethernet frame
	FrameRepair FrameType = 0x02 // FEC repair symbol
	FrameAuth   FrameType = 0x10 // handshake/auth
	FramePing   FrameType = 0x20
	FramePong   FrameType = 0x21
)

const (
	HeaderSize = 1 + 2 + 4 + 8 // type + hub_id + session_id + seq
	MaxPayload = 1472           // MTU 1500 - UDP 28 - HeaderSize 15
)

type Header struct {
	Type      FrameType
	HubID     uint16
	SessionID uint32
	Seq       uint64
}

func (h Header) Marshal(dst []byte) {
	dst[0] = byte(h.Type)
	binary.BigEndian.PutUint16(dst[1:3], h.HubID)
	binary.BigEndian.PutUint32(dst[3:7], h.SessionID)
	binary.BigEndian.PutUint64(dst[7:15], h.Seq)
}

func ParseHeader(src []byte) (Header, bool) {
	if len(src) < HeaderSize {
		return Header{}, false
	}
	return Header{
		Type:      FrameType(src[0]),
		HubID:     binary.BigEndian.Uint16(src[1:3]),
		SessionID: binary.BigEndian.Uint32(src[3:7]),
		Seq:       binary.BigEndian.Uint64(src[7:15]),
	}, true
}
