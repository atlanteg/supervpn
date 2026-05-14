package auth

import (
	"strings"
	"testing"
)

// TestHashAndCheck: HashPassword then CheckPassword with the same password succeeds.
func TestHashAndCheck(t *testing.T) {
	plain := "correcthorsebatterystaple"
	hash, err := HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty string")
	}
	if err := CheckPassword(plain, hash); err != nil {
		t.Errorf("CheckPassword with correct password failed: %v", err)
	}
}

// TestCheckPassword_WrongPassword: CheckPassword with wrong password returns ErrBadCredentials.
func TestCheckPassword_WrongPassword(t *testing.T) {
	hash, err := HashPassword("rightpassword")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	err = CheckPassword("wrongpassword", hash)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if err != ErrBadCredentials {
		t.Errorf("expected ErrBadCredentials, got %v", err)
	}
}

// TestWireHash_Deterministic: same password always produces the same hex string.
func TestWireHash_Deterministic(t *testing.T) {
	pw := "my-secret-password"
	h1 := WireHash(pw)
	h2 := WireHash(pw)
	if h1 != h2 {
		t.Errorf("WireHash is non-deterministic: %q != %q", h1, h2)
	}
}

// TestWireHash_Length: WireHash always returns a 64-character hex string (SHA-256).
func TestWireHash_Length(t *testing.T) {
	passwords := []string{"", "a", "short", "a much longer password with spaces", "特殊文字"}
	for _, pw := range passwords {
		h := WireHash(pw)
		if len(h) != 64 {
			t.Errorf("WireHash(%q): expected 64 chars, got %d: %q", pw, len(h), h)
		}
		// Verify it's valid hex
		validHex := true
		for _, c := range h {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				validHex = false
				break
			}
		}
		if !validHex {
			t.Errorf("WireHash(%q): not valid lowercase hex: %q", pw, h)
		}
	}
}

// TestWireHash_Different: different passwords produce different hashes.
func TestWireHash_Different(t *testing.T) {
	pairs := [][2]string{
		{"password", "Password"},
		{"abc", "abd"},
		{"", "a"},
		{"hello", "hello "},
	}
	for _, pair := range pairs {
		h1 := WireHash(pair[0])
		h2 := WireHash(pair[1])
		if h1 == h2 {
			t.Errorf("WireHash(%q) == WireHash(%q): both are %q", pair[0], pair[1], h1)
		}
	}
}

// TestHashPassword_Unique: two calls with the same password produce different bcrypt hashes (salt).
func TestHashPassword_Unique(t *testing.T) {
	plain := "same-password"
	h1, err := HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword call 1: %v", err)
	}
	h2, err := HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword call 2: %v", err)
	}
	if h1 == h2 {
		t.Error("two HashPassword calls for the same password should produce different hashes (bcrypt salt)")
	}
	// Both must still verify correctly
	if err := CheckPassword(plain, h1); err != nil {
		t.Errorf("CheckPassword failed for hash 1: %v", err)
	}
	if err := CheckPassword(plain, h2); err != nil {
		t.Errorf("CheckPassword failed for hash 2: %v", err)
	}
}

// TestHashPassword_IsBcrypt: bcrypt hashes start with "$2a$" or "$2b$".
func TestHashPassword_IsBcrypt(t *testing.T) {
	hash, err := HashPassword("testpw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("HashPassword output doesn't look like bcrypt: %q", hash)
	}
}

// TestCheckPassword_EmptyPassword: empty password against its hash works.
func TestCheckPassword_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword empty: %v", err)
	}
	if err := CheckPassword("", hash); err != nil {
		t.Errorf("CheckPassword with empty password failed: %v", err)
	}
	if err := CheckPassword("notempty", hash); err != ErrBadCredentials {
		t.Errorf("expected ErrBadCredentials for non-empty vs empty hash, got %v", err)
	}
}
