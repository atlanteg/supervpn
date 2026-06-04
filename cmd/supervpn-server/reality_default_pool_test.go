package main

import (
	"testing"

	"github.com/atlanteg/supervpn/internal/transport"
)

// TestDefaultPoolMatchesClientPool guards against a regenerated default private
// pool drifting out of sync with the public pool embedded in clients: every
// default private key's public half must appear in the client pool, or
// zero-config clients would fail to authenticate.
func TestDefaultPoolMatchesClientPool(t *testing.T) {
	if len(defaultRealityPrivatePool) == 0 {
		t.Skip("default pool empty")
	}
	if len(defaultRealityPrivatePool) != transport.RealityPublicPoolSize() {
		t.Fatalf("default private pool (%d) != client public pool (%d)",
			len(defaultRealityPrivatePool), transport.RealityPublicPoolSize())
	}
	for i, privB64 := range defaultRealityPrivatePool {
		priv, err := transport.DecodeRealityPrivateKey(privB64)
		if err != nil {
			t.Fatalf("default priv[%d] invalid: %v", i, err)
		}
		pub := transport.EncodeRealityKey(priv.PublicKey().Bytes())
		if !transport.RealityPublicPoolContains(pub) {
			t.Errorf("default priv[%d] public half not in client pool", i)
		}
	}
}
