package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// ErrReplay is returned by Open when a packet's counter falls within the
// already-seen replay window. The packet is a duplicate, not a real error.
var ErrReplay = errors.New("replay detected")

// Packet format:
// [ peer_id: 4 bytes ][ counter: 8 bytes ][ nonce: 12 bytes ][ ciphertext+tag ]
const (
	HeaderSize = 4 + 8 + 12
	TagSize    = 16
	MaxPktSize = 1500
	MinPktSize = HeaderSize + TagSize
)

type Cipher struct {
	aead    cipher.AEAD
	counter uint64
	mu      sync.Mutex
	peerID  uint32
	salt    [4]byte // per-session random; occupies nonce[8:12], prevents nonce reuse across sessions
}

// DeriveKey computes a pairwise key from the token, network name, and the two
// node names. Order of node names does not matter: key(A,B) == key(B,A).
// Including networkName ensures nodes on different networks never share keys
// even if they use the same token.
func DeriveKey(token, networkName, nameA, nameB string) ([]byte, error) {
	if token == "" {
		return nil, fmt.Errorf("token is empty")
	}
	a, b := nameA, nameB
	if a > b {
		a, b = b, a
	}
	info := fmt.Sprintf("myvpn-tunnel:%s:%s:%s", networkName, a, b)
	master := sha256.Sum256([]byte(token))
	r := hkdf.New(sha256.New, master[:], nil, []byte(info))
	key := make([]byte, 16)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// NewCipher creates a cipher from a raw key (16 bytes for AES-128-GCM).
// A 4-byte random session salt is generated once here and mixed into every
// nonce, ensuring nonce uniqueness across sessions even when the counter resets.
func NewCipher(key []byte, peerID uint32) (*Cipher, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("key too short: need 16 bytes")
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	c := &Cipher{aead: aead, peerID: peerID}
	if _, err := io.ReadFull(rand.Reader, c.salt[:]); err != nil {
		return nil, fmt.Errorf("generate session salt: %w", err)
	}
	return c, nil
}

// Seal encrypts plaintext and returns a ready-to-send packet
func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	c.counter++
	cnt := c.counter
	c.mu.Unlock()

	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], cnt)
	copy(nonce[8:], c.salt[:])

	buf := make([]byte, HeaderSize, HeaderSize+len(plaintext)+TagSize)
	binary.BigEndian.PutUint32(buf[0:4], c.peerID)
	binary.BigEndian.PutUint64(buf[4:12], cnt)
	copy(buf[12:24], nonce[:])

	buf = c.aead.Seal(buf, nonce[:], plaintext, buf[:4])
	return buf, nil
}

// Open decrypts an incoming packet and checks for replay via a 512-slot sliding window
func (c *Cipher) Open(pkt []byte, replay *ReplayWindow) ([]byte, error) {
	if len(pkt) < MinPktSize {
		return nil, fmt.Errorf("packet too short: %d", len(pkt))
	}

	cnt := binary.BigEndian.Uint64(pkt[4:12])
	var nonce [12]byte
	copy(nonce[:], pkt[12:24])

	if !replay.Check(cnt) {
		return nil, ErrReplay
	}

	plain, err := c.aead.Open(nil, nonce[:], pkt[HeaderSize:], pkt[:4])
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plain, nil
}

const replayWindowSize = 512 // bits; tolerates ~120ms reordering at 4 kpps

// ReplayWindow protects against replay attacks while tolerating UDP reordering.
// Sliding window of 512 positions from the highest counter seen.
type ReplayWindow struct {
	mu      sync.Mutex
	maxSeen uint64
	window  [8]uint64 // 8 × 64 = 512-bit sliding window; window[0] bit-0 = maxSeen
}

func (w *ReplayWindow) Check(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if counter == 0 {
		return false
	}

	if counter > w.maxSeen {
		shift := counter - w.maxSeen
		if shift >= replayWindowSize {
			w.window = [8]uint64{}
		} else {
			wordShift := int(shift / 64)
			bitShift := shift % 64
			// Left-shift the 512-bit window: older bits move to higher word/bit indices.
			// Process from high to low so source words are not overwritten before use.
			for i := 7; i >= 0; i-- {
				src := i - wordShift
				if src < 0 {
					w.window[i] = 0
				} else if bitShift == 0 {
					w.window[i] = w.window[src]
				} else {
					w.window[i] = w.window[src] << bitShift
					if src > 0 {
						w.window[i] |= w.window[src-1] >> (64 - bitShift)
					}
				}
			}
		}
		w.window[0] |= 1 // mark the new maxSeen at bit 0
		w.maxSeen = counter
		return true
	}

	diff := w.maxSeen - counter
	if diff >= replayWindowSize {
		return false
	}

	word := diff / 64
	bit := diff % 64
	mask := uint64(1) << bit
	if w.window[word]&mask != 0 {
		return false
	}
	w.window[word] |= mask
	return true
}
