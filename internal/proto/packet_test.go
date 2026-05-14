package proto

import (
	"bytes"
	"strings"
	"testing"
)

// TestHeader_MarshalParse: marshal a Header and parse it back; all fields must match.
func TestHeader_MarshalParse(t *testing.T) {
	original := Header{
		Type:      FrameData,
		HubID:     0x1234,
		SessionID: 0xDEADBEEF,
		Seq:       0xCAFEBABE12345678,
	}

	buf := make([]byte, HeaderSize)
	original.Marshal(buf)

	parsed, ok := ParseHeader(buf)
	if !ok {
		t.Fatal("ParseHeader returned false for a valid buffer")
	}
	if parsed.Type != original.Type {
		t.Errorf("Type: got %v, want %v", parsed.Type, original.Type)
	}
	if parsed.HubID != original.HubID {
		t.Errorf("HubID: got %v, want %v", parsed.HubID, original.HubID)
	}
	if parsed.SessionID != original.SessionID {
		t.Errorf("SessionID: got %v, want %v", parsed.SessionID, original.SessionID)
	}
	if parsed.Seq != original.Seq {
		t.Errorf("Seq: got %v, want %v", parsed.Seq, original.Seq)
	}
}

// TestHeader_AllFrameTypes: each defined FrameType survives a round-trip.
func TestHeader_AllFrameTypes(t *testing.T) {
	types := []FrameType{FrameData, FrameRepair, FrameAuth, FramePing, FramePong}
	for _, ft := range types {
		h := Header{Type: ft, HubID: 1, SessionID: 2, Seq: 3}
		buf := make([]byte, HeaderSize)
		h.Marshal(buf)
		got, ok := ParseHeader(buf)
		if !ok || got.Type != ft {
			t.Errorf("FrameType %v: round-trip failed (ok=%v type=%v)", ft, ok, got.Type)
		}
	}
}

// TestHeader_TooShort: ParseHeader with insufficient data must return false.
func TestHeader_TooShort(t *testing.T) {
	for n := 0; n < HeaderSize; n++ {
		buf := make([]byte, n)
		_, ok := ParseHeader(buf)
		if ok {
			t.Errorf("ParseHeader with %d bytes should return false (need %d)", n, HeaderSize)
		}
	}
}

// TestAuthHello_RoundTrip: marshal AuthHello and parse it back; fields must match.
func TestAuthHello_RoundTrip(t *testing.T) {
	var pwhash [32]byte
	for i := range pwhash {
		pwhash[i] = byte(i)
	}
	original := AuthHello{
		HubID:  0xABCD,
		Login:  "alice",
		PWHash: pwhash,
	}

	data := original.Marshal()
	parsed, err := ParseAuthHello(data)
	if err != nil {
		t.Fatalf("ParseAuthHello: %v", err)
	}
	if parsed.HubID != original.HubID {
		t.Errorf("HubID: got %v, want %v", parsed.HubID, original.HubID)
	}
	if parsed.Login != original.Login {
		t.Errorf("Login: got %q, want %q", parsed.Login, original.Login)
	}
	if parsed.PWHash != original.PWHash {
		t.Errorf("PWHash mismatch")
	}
}

// TestAuthHello_EmptyLogin: login can be empty (zero-length).
func TestAuthHello_EmptyLogin(t *testing.T) {
	var pwhash [32]byte
	original := AuthHello{HubID: 1, Login: "", PWHash: pwhash}
	data := original.Marshal()
	parsed, err := ParseAuthHello(data)
	if err != nil {
		t.Fatalf("ParseAuthHello empty login: %v", err)
	}
	if parsed.Login != "" {
		t.Errorf("expected empty login, got %q", parsed.Login)
	}
}

// TestAuthHello_TooShort: ParseAuthHello must return error for truncated buffers.
func TestAuthHello_TooShort(t *testing.T) {
	// Minimum valid buffer: hub_id(2) + login_len(1) + pwhash(32) = 35 bytes with empty login
	for n := 0; n < 2+1+32; n++ {
		buf := make([]byte, n)
		_, err := ParseAuthHello(buf)
		if err == nil {
			t.Errorf("ParseAuthHello with %d bytes should return error", n)
		}
	}
}

// TestAuthHello_TruncatedLogin: ParseAuthHello returns error when login_len > available bytes.
func TestAuthHello_TruncatedLogin(t *testing.T) {
	// hub_id(2) + login_len=5 byte, then only 2 bytes of login + 32 of pwhash = truncated
	buf := make([]byte, 2+1+2+32) // login_len says 5 but we only give 2 bytes of login
	buf[2] = 5                    // login_len = 5
	_, err := ParseAuthHello(buf)
	if err == nil {
		t.Error("ParseAuthHello should fail when login bytes are truncated")
	}
}

// TestAuthOK_RoundTrip: marshal and parse AuthOK; SessionID must match.
func TestAuthOK_RoundTrip(t *testing.T) {
	original := AuthOK{SessionID: 0x12345678}
	data := original.Marshal()

	parsed, err := ParseAuthOK(data)
	if err != nil {
		t.Fatalf("ParseAuthOK: %v", err)
	}
	if parsed.SessionID != original.SessionID {
		t.Errorf("SessionID: got %v, want %v", parsed.SessionID, original.SessionID)
	}
}

// TestAuthOK_TooShort: ParseAuthOK must return error when buffer < 4 bytes.
func TestAuthOK_TooShort(t *testing.T) {
	for n := 0; n < 4; n++ {
		_, err := ParseAuthOK(make([]byte, n))
		if err == nil {
			t.Errorf("ParseAuthOK with %d bytes should return error", n)
		}
	}
}

// TestAuthError_RoundTrip: marshal/parse AuthError with a 128-char message.
func TestAuthError_RoundTrip(t *testing.T) {
	msg := strings.Repeat("x", 128)
	original := AuthError{Message: msg}
	data := original.Marshal()

	parsed, err := ParseAuthError(data)
	if err != nil {
		t.Fatalf("ParseAuthError: %v", err)
	}
	if parsed.Message != msg {
		t.Errorf("Message mismatch: got %q, want %q", parsed.Message, msg)
	}
}

// TestAuthError_EmptyMessage: AuthError with empty message round-trips.
func TestAuthError_EmptyMessage(t *testing.T) {
	original := AuthError{Message: ""}
	data := original.Marshal()

	parsed, err := ParseAuthError(data)
	if err != nil {
		t.Fatalf("ParseAuthError: %v", err)
	}
	if parsed.Message != "" {
		t.Errorf("expected empty message, got %q", parsed.Message)
	}
}

// TestAuthError_MessageTruncated: message > 255 bytes is truncated to 255.
func TestAuthError_MessageTruncated(t *testing.T) {
	// 300 bytes — should be silently truncated to 255 on Marshal
	long := strings.Repeat("a", 300)
	original := AuthError{Message: long}
	data := original.Marshal()

	// The first byte is the length field
	if len(data) < 1 {
		t.Fatal("marshalled AuthError is empty")
	}
	msgLen := int(data[0])
	if msgLen != 255 {
		t.Errorf("expected msg_len=255 after truncation, got %d", msgLen)
	}
	if len(data) != 1+255 {
		t.Errorf("expected data length 256 (1+255), got %d", len(data))
	}

	parsed, err := ParseAuthError(data)
	if err != nil {
		t.Fatalf("ParseAuthError after truncation: %v", err)
	}
	if len(parsed.Message) != 255 {
		t.Errorf("expected 255-char parsed message, got %d", len(parsed.Message))
	}
}

// TestAuthError_TooShort: ParseAuthError must error on zero-length buffer.
func TestAuthError_TooShort(t *testing.T) {
	_, err := ParseAuthError(nil)
	if err == nil {
		t.Error("ParseAuthError(nil) should return error")
	}
	_, err = ParseAuthError([]byte{})
	if err == nil {
		t.Error("ParseAuthError([]) should return error")
	}
}

// TestHeader_MarshalParse_LargerBuffer: Marshal into a larger buffer; only first HeaderSize bytes are used.
func TestHeader_MarshalParse_LargerBuffer(t *testing.T) {
	h := Header{Type: FrameRepair, HubID: 7, SessionID: 99, Seq: 12345}
	buf := make([]byte, HeaderSize+100)
	for i := range buf {
		buf[i] = 0xFF // fill with sentinel
	}
	h.Marshal(buf)

	parsed, ok := ParseHeader(buf)
	if !ok {
		t.Fatal("ParseHeader should succeed with larger buffer")
	}
	if parsed.HubID != 7 || parsed.SessionID != 99 || parsed.Seq != 12345 {
		t.Error("Parsed fields do not match original")
	}
}

// TestAuthHello_LongLogin: long login string round-trips correctly.
func TestAuthHello_LongLogin(t *testing.T) {
	// Login length is encoded in 1 byte, so max is 255.
	login := strings.Repeat("u", 200)
	var pwhash [32]byte
	pwhash[0] = 0xAB
	original := AuthHello{HubID: 5, Login: login, PWHash: pwhash}
	data := original.Marshal()

	parsed, err := ParseAuthHello(data)
	if err != nil {
		t.Fatalf("ParseAuthHello long login: %v", err)
	}
	if parsed.Login != login {
		t.Errorf("Login mismatch: got len=%d, want len=%d", len(parsed.Login), len(login))
	}
	if !bytes.Equal(parsed.PWHash[:], pwhash[:]) {
		t.Error("PWHash mismatch after long login round-trip")
	}
}
