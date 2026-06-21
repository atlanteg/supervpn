// Package proto defines the wire format for supervpn packets.
//
// Frame layout (UDP payload):
//
//	[frame_type: 1][hub_id: 2][session_id: 4][seq: 8][payload...]
//
// For FEC repair frames, payload contains the repair block header + repair symbols.
package proto

import (
	"encoding/binary"
	"fmt"
)

type FrameType uint8

const (
	FrameData     FrameType = 0x01 // encrypted L2 Ethernet frame
	FrameRepair   FrameType = 0x02 // FEC repair symbol
	FrameJoin     FrameType = 0x03 // register secondary path (no payload; SessionID identifies session)
	FrameAuth     FrameType = 0x10 // handshake/auth
	FrameListHubs FrameType = 0x11 // pre-auth hub discovery (no credentials required)
	FramePing     FrameType = 0x20
	FramePong     FrameType = 0x21
	// In-band software update over the (DPI-resistant) transport. Pre-auth, used
	// as a fallback when GitHub and the HTTP mirrors are blocked. Only meaningful
	// over a reliable stream transport (Reality/TCP).
	FrameUpdateGet  FrameType = 0x30 // client→server: payload = asset name (raw bytes)
	FrameUpdateData FrameType = 0x31 // server→client: payload = [1 byte status][chunk]
)

// FrameUpdateData status byte (first payload byte).
const (
	UpdateChunk byte = 0 // a chunk of asset data follows
	UpdateEOF   byte = 1 // end of asset; no data
	UpdateErr   byte = 2 // error; rest of payload is a UTF-8 message
)

const (
	HeaderSize = 1 + 2 + 4 + 8 // type + hub_id + session_id + seq
	MaxPayload = 1472          // MTU 1500 - UDP 28 - HeaderSize 15
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

// FEC metadata is packed into the Header.Seq field.
//
// For FrameData:
//
//	[block_id: 4 bytes][pkt_idx: 2 bytes][padding: 2 bytes]
//
// For FrameRepair:
//
//	[block_id: 4 bytes][repair_idx: 1 byte][block_k: 1 byte][block_r: 1 byte][padding: 1 byte]

// PackDataSeq packs FEC block metadata for a FrameData frame.
func PackDataSeq(blockID uint32, pktIdx uint16) uint64 {
	return uint64(blockID)<<32 | uint64(pktIdx)<<16
}

// UnpackDataSeq extracts FEC metadata from a FrameData Seq field.
func UnpackDataSeq(seq uint64) (blockID uint32, pktIdx uint16) {
	return uint32(seq >> 32), uint16(seq >> 16)
}

// PackRepairSeq packs FEC metadata for a FrameRepair frame.
func PackRepairSeq(blockID uint32, repairIdx, blockK, blockR uint8) uint64 {
	return uint64(blockID)<<32 | uint64(repairIdx)<<24 | uint64(blockK)<<16 | uint64(blockR)<<8
}

// UnpackRepairSeq extracts FEC metadata from a FrameRepair Seq field.
func UnpackRepairSeq(seq uint64) (blockID uint32, repairIdx, blockK, blockR uint8) {
	return uint32(seq >> 32), uint8(seq >> 24), uint8(seq >> 16), uint8(seq >> 8)
}

// Auth sub-message types (first byte of FrameAuth payload)
const (
	AuthMsgHello uint8 = 0x01
	AuthMsgOK    uint8 = 0x02
	AuthMsgError uint8 = 0xFF
)

// AuthHello is sent by client inside a FrameAuth frame to initiate a session.
// Binary: [sub_type:1=0x01][hub_id:2][login_len:1][login:N][pwhash:32]
type AuthHello struct {
	HubID  uint16
	Login  string
	PWHash [32]byte // raw SHA-256 of password
}

func (a AuthHello) Marshal() []byte {
	loginBytes := []byte(a.Login)
	buf := make([]byte, 2+1+len(loginBytes)+32)
	binary.BigEndian.PutUint16(buf[0:2], a.HubID)
	buf[2] = uint8(len(loginBytes))
	copy(buf[3:], loginBytes)
	copy(buf[3+len(loginBytes):], a.PWHash[:])
	return buf
}

func ParseAuthHello(b []byte) (AuthHello, error) {
	// b starts after the sub_type byte
	// layout: [hub_id:2][login_len:1][login:N][pwhash:32]
	if len(b) < 2+1+32 {
		return AuthHello{}, fmt.Errorf("proto: AuthHello too short")
	}
	hubID := binary.BigEndian.Uint16(b[0:2])
	loginLen := int(b[2])
	if len(b) < 2+1+loginLen+32 {
		return AuthHello{}, fmt.Errorf("proto: AuthHello truncated (login_len=%d)", loginLen)
	}
	login := string(b[3 : 3+loginLen])
	var pwhash [32]byte
	copy(pwhash[:], b[3+loginLen:3+loginLen+32])
	return AuthHello{HubID: hubID, Login: login, PWHash: pwhash}, nil
}

// AuthOK is sent by server on success.
// Binary: [sub_type:1=0x02][session_id:4][fec_k:1][fec_r:1][fec_repair_delay_ms:2]
//
// FecK, FecR and FecRepairDelay carry the server's active FEC parameters so
// clients can adopt them automatically without manual config alignment.
// All three fields are 0 when the server does not advertise FEC params.
// ParseAuthOK tolerates old shorter messages for backward compatibility.
type AuthOK struct {
	SessionID      uint32
	FecK           uint8  // server's FEC K (data pkts per block); 0 = not advertised
	FecR           uint8  // server's FEC R (repair pkts per block); 0 = not advertised
	FecRepairDelay uint16 // server's repair_delay in ms; 0 = not advertised
}

func (a AuthOK) Marshal() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], a.SessionID)
	buf[4] = a.FecK
	buf[5] = a.FecR
	binary.BigEndian.PutUint16(buf[6:8], a.FecRepairDelay)
	return buf
}

func ParseAuthOK(b []byte) (AuthOK, error) {
	// b starts after the sub_type byte
	if len(b) < 4 {
		return AuthOK{}, fmt.Errorf("proto: AuthOK too short")
	}
	ok := AuthOK{SessionID: binary.BigEndian.Uint32(b[0:4])}
	if len(b) >= 6 {
		ok.FecK = b[4]
		ok.FecR = b[5]
	}
	if len(b) >= 8 {
		ok.FecRepairDelay = binary.BigEndian.Uint16(b[6:8])
	}
	return ok, nil
}

// AuthError is sent by server on failure.
// Binary: [sub_type:1=0xFF][msg_len:1][msg:N]
type AuthError struct {
	Message string
}

func (a AuthError) Marshal() []byte {
	msgBytes := []byte(a.Message)
	if len(msgBytes) > 255 {
		msgBytes = msgBytes[:255]
	}
	buf := make([]byte, 1+len(msgBytes))
	buf[0] = uint8(len(msgBytes))
	copy(buf[1:], msgBytes)
	return buf
}

func ParseAuthError(b []byte) (AuthError, error) {
	// b starts after the sub_type byte
	if len(b) < 1 {
		return AuthError{}, fmt.Errorf("proto: AuthError too short")
	}
	msgLen := int(b[0])
	if len(b) < 1+msgLen {
		return AuthError{}, fmt.Errorf("proto: AuthError truncated (msg_len=%d)", msgLen)
	}
	return AuthError{Message: string(b[1 : 1+msgLen])}, nil
}

// HubInfo is one entry in a FrameListHubs response.
type HubInfo struct {
	ID   uint16
	Name string
}

// MarshalHubList encodes a hub list for a FrameListHubs response payload.
// Binary: [count:1][{id:2, name_len:1, name:N}...]
func MarshalHubList(hubs []HubInfo) []byte {
	n := len(hubs)
	if n > 255 {
		n = 255
	}
	buf := []byte{byte(n)}
	for _, h := range hubs[:n] {
		name := []byte(h.Name)
		if len(name) > 255 {
			name = name[:255]
		}
		entry := make([]byte, 3+len(name))
		binary.BigEndian.PutUint16(entry[0:2], h.ID)
		entry[2] = byte(len(name))
		copy(entry[3:], name)
		buf = append(buf, entry...)
	}
	return buf
}

// ParseHubList decodes a FrameListHubs response payload.
func ParseHubList(b []byte) ([]HubInfo, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("proto: hub list empty")
	}
	count := int(b[0])
	b = b[1:]
	hubs := make([]HubInfo, 0, count)
	for i := 0; i < count; i++ {
		if len(b) < 3 {
			return nil, fmt.Errorf("proto: hub list truncated at entry %d", i)
		}
		id := binary.BigEndian.Uint16(b[0:2])
		nameLen := int(b[2])
		b = b[3:]
		if len(b) < nameLen {
			return nil, fmt.Errorf("proto: hub name truncated at entry %d", i)
		}
		hubs = append(hubs, HubInfo{ID: id, Name: string(b[:nameLen])})
		b = b[nameLen:]
	}
	return hubs, nil
}
