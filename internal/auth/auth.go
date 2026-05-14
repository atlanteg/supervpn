// Package auth handles client authentication to a hub.
//
// Protocol (over encrypted channel):
//  1. Client → Server: AuthRequest{hub, login, password_hash}
//  2. Server → Client: AuthResponse{ok, session_id, error}
//
// Passwords are stored as bcrypt hashes in server config.
// password_hash on the wire = SHA-256(password) — server re-hashes with bcrypt for storage.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var ErrBadCredentials = errors.New("auth: invalid login or password")

type Credentials struct {
	Login    string
	Password string
}

// HashPassword returns bcrypt hash for storage.
func HashPassword(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword verifies plain password against stored bcrypt hash.
func CheckPassword(plain, stored string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(plain)); err != nil {
		return ErrBadCredentials
	}
	return nil
}

// WireHash computes the on-wire password representation (SHA-256 hex).
// The server receives this and calls CheckPassword(wireHash, storedBcrypt).
func WireHash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
