package transport

// Reality-style authentication shared by the client dialer and the server
// listener.  The scheme mirrors XTLS-Reality's externally-visible behaviour
// without being wire-compatible with it (our own client only):
//
//   - The client offers a normal X25519 key_share in its (uTLS) ClientHello.
//   - Both sides derive a shared secret via X25519 between the client's TLS
//     ephemeral key and the server's long-term Reality key.
//   - The client encrypts (shortID ‖ unix-time) with AES-128-GCM under a key
//     derived from that shared secret and places the 32-byte result in the
//     ClientHello session_id field.
//   - The server recomputes the shared secret from the key_share it parsed out
//     of the ClientHello, opens the GCM blob, and accepts the client iff the
//     tag verifies, the shortID is allowed, and the timestamp is fresh.
//
// A prober cannot forge a valid session_id without the server's public key, so
// its GCM open fails and the server falls back to proxying the real dest site.
//
// AES-128-GCM (not 256) matches the project-wide "speed over strength" choice.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

const (
	// realityShortIDLen is the fixed plaintext width of a shortID (zero-padded).
	realityShortIDLen = 8
	// realitySessionIDLen is the TLS session_id width that carries the auth blob:
	// 16-byte GCM ciphertext (8-byte shortID + 8-byte time) + 16-byte tag.
	realitySessionIDLen = 32
	// realityKDFLabel domain-separates the AES key derivation.
	realityKDFLabel = "supervpn-reality-v1"
)

// realityTimeWindowDefault is the default ± tolerance (seconds) for the
// timestamp embedded in the auth blob, absorbing client/server clock skew.
const realityTimeWindowDefault = 90

// GenerateRealityKeyPair returns a fresh X25519 keypair (raw 32-byte priv/pub).
func GenerateRealityKeyPair() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// EncodeRealityKey base64(std)-encodes a raw key for storage in TOML.
func EncodeRealityKey(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

// DecodeRealityPrivateKey parses a base64 X25519 private key.
func DecodeRealityPrivateKey(s string) (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("reality: decode private key: %w", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("reality: invalid private key: %w", err)
	}
	return k, nil
}

// DecodeRealityPublicKey parses a base64 X25519 public key.
func DecodeRealityPublicKey(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("reality: decode public key: %w", err)
	}
	k, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("reality: invalid public key: %w", err)
	}
	return k, nil
}

// ParseShortID converts a hex-ish shortID string to a fixed 8-byte array.
// Accepts any string up to 8 bytes; it is truncated/zero-padded to 8 bytes so
// the operator can use short human-readable identifiers.
func ParseShortID(s string) [realityShortIDLen]byte {
	var out [realityShortIDLen]byte
	copy(out[:], s)
	return out
}

// realityAEAD builds the AES-128-GCM AEAD from a shared secret.
func realityAEAD(shared []byte) (cipher.AEAD, error) {
	sum := sha256.Sum256(append([]byte(realityKDFLabel), shared...))
	block, err := aes.NewCipher(sum[:16]) // AES-128
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealRealityAuth produces the 32-byte session_id blob.
// nonce must be 12 bytes (taken from ClientHello random); shortID is the
// caller's identifier; unixTime is the current time in seconds.
func sealRealityAuth(shared, nonce []byte, shortID [realityShortIDLen]byte, unixTime int64) ([]byte, error) {
	aead, err := realityAEAD(shared)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, realityShortIDLen+8)
	copy(plain[:realityShortIDLen], shortID[:])
	binary.BigEndian.PutUint64(plain[realityShortIDLen:], uint64(unixTime))
	out := aead.Seal(nil, nonce[:12], plain, nil)
	if len(out) != realitySessionIDLen {
		return nil, fmt.Errorf("reality: auth blob size %d != %d", len(out), realitySessionIDLen)
	}
	return out, nil
}

// openRealityAuth verifies a session_id blob. It returns the embedded shortID
// and timestamp on success. ok is false when the GCM tag does not verify
// (i.e. the peer did not know the server key — treat as a prober).
func openRealityAuth(shared, nonce, sessionID []byte) (shortID [realityShortIDLen]byte, unixTime int64, ok bool) {
	if len(sessionID) != realitySessionIDLen || len(nonce) < 12 {
		return shortID, 0, false
	}
	aead, err := realityAEAD(shared)
	if err != nil {
		return shortID, 0, false
	}
	plain, err := aead.Open(nil, nonce[:12], sessionID, nil)
	if err != nil || len(plain) != realityShortIDLen+8 {
		return shortID, 0, false
	}
	copy(shortID[:], plain[:realityShortIDLen])
	unixTime = int64(binary.BigEndian.Uint64(plain[realityShortIDLen:]))
	return shortID, unixTime, true
}

// shortIDAllowed reports whether id is in the allowed set (constant-time per entry).
func shortIDAllowed(id [realityShortIDLen]byte, allowed [][realityShortIDLen]byte) bool {
	for _, a := range allowed {
		if subtle.ConstantTimeCompare(id[:], a[:]) == 1 {
			return true
		}
	}
	return false
}
