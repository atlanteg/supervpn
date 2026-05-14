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
// Binary: [sub_type:1=0x02][session_id:4]
type AuthOK struct {
	SessionID uint32
}

func (a AuthOK) Marshal() []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, a.SessionID)
	return buf
}

func ParseAuthOK(b []byte) (AuthOK, error) {
	// b starts after the sub_type byte
	if len(b) < 4 {
		return AuthOK{}, fmt.Errorf("proto: AuthOK too short")
	}
	return AuthOK{SessionID: binary.BigEndian.Uint32(b[0:4])}, nil
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
