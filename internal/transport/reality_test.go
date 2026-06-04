package transport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func mustKeyPair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv, pub, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return EncodeRealityKey(priv), EncodeRealityKey(pub)
}

// sharedFor computes the X25519 shared secret the way both ends do.
func sharedFor(t *testing.T, aPrivB64, bPubB64 string) []byte {
	t.Helper()
	a, err := DecodeRealityPrivateKey(aPrivB64)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	b, err := DecodeRealityPublicKey(bPubB64)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	s, err := a.ECDH(b)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return s
}

func TestRealityAuthRoundTrip(t *testing.T) {
	privB64, pubB64 := mustKeyPair(t)
	shared := sharedFor(t, privB64, pubB64) // priv·pub == pub·priv

	nonce := make([]byte, 32)
	rand.Read(nonce)
	shortID := ParseShortID("test")
	now := time.Now().Unix()

	blob, err := sealRealityAuth(shared, nonce, shortID, now)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(blob) != realitySessionIDLen {
		t.Fatalf("blob len %d != %d", len(blob), realitySessionIDLen)
	}

	gotID, gotTime, ok := openRealityAuth(shared, nonce, blob)
	if !ok {
		t.Fatal("open failed for valid blob")
	}
	if gotID != shortID {
		t.Errorf("shortID mismatch: %x != %x", gotID, shortID)
	}
	if gotTime != now {
		t.Errorf("time mismatch: %d != %d", gotTime, now)
	}

	// Wrong shared secret must not open.
	wrong := make([]byte, len(shared))
	copy(wrong, shared)
	wrong[0] ^= 0xff
	if _, _, ok := openRealityAuth(wrong, nonce, blob); ok {
		t.Error("open succeeded with wrong shared secret")
	}
}

// echoServer accepts one Reality connection, expects authorization, then echoes
// one frame back.
func realityEchoOnce(t *testing.T, ln net.Listener, params RealityServerParams) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	tr, authorized, err := AcceptReality(context.Background(), conn, params)
	if err != nil {
		t.Errorf("AcceptReality: %v", err)
		return
	}
	if !authorized {
		t.Error("expected authorized client")
		return
	}
	defer tr.Close()
	f, err := tr.Recv(context.Background())
	if err != nil {
		t.Errorf("server recv: %v", err)
		return
	}
	if err := tr.Send(Frame{Data: f.Data}); err != nil {
		t.Errorf("server send: %v", err)
	}
}

func TestRealityAuthorizedEndToEnd(t *testing.T) {
	privB64, pubB64 := mustKeyPair(t)
	params, err := BuildRealityServerParams(privB64, "127.0.0.1:9", []string{"test"}, 90, "", "")
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go realityEchoOnce(t, ln, params)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr, err := DialReality(ctx, RealityClientParams{
		Addr:        ln.Addr().String(),
		SNI:         "www.microsoft.com",
		PublicKey:   pubB64,
		ShortID:     "test",
		Fingerprint: "chrome",
	})
	if err != nil {
		t.Fatalf("DialReality: %v", err)
	}
	defer tr.Close()
	if tr.Mode() != "reality" {
		t.Errorf("mode = %q, want reality", tr.Mode())
	}

	payload := []byte("hello-reality")
	if err := tr.Send(Frame{Data: payload}); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := tr.Recv(ctx)
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if !bytes.Equal(got.Data, payload) {
		t.Errorf("echo mismatch: %q != %q", got.Data, payload)
	}
}

func TestRealityProberFallbackToDest(t *testing.T) {
	// Fake "real site" that greets every connection with a banner.
	const banner = "REAL-SITE-BANNER"
	dest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dest listen: %v", err)
	}
	defer dest.Close()
	go func() {
		for {
			c, err := dest.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(banner))
			}(c)
		}
	}()

	privB64, _ := mustKeyPair(t)
	params, err := BuildRealityServerParams(privB64, dest.Addr().String(), []string{"test"}, 90, "", "")
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, authorized, _ := AcceptReality(context.Background(), conn, params)
		if authorized {
			t.Error("prober must not be authorized")
		}
	}()

	// Prober: connect and send a non-TLS-handshake byte stream.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("prober dial: %v", err)
	}
	defer c.Close()
	c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf, err := io.ReadAll(io.LimitReader(c, int64(len(banner))))
	if err != nil && err != io.EOF {
		t.Fatalf("prober read: %v", err)
	}
	if string(buf) != banner {
		t.Errorf("prober got %q, want dest banner %q", buf, banner)
	}
}

// Sanity: the X25519 group constant matches crypto/ecdh expectations.
func TestX25519KeySizes(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.PublicKey().Bytes()) != 32 {
		t.Fatalf("pub size %d", len(k.PublicKey().Bytes()))
	}
}
