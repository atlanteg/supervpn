package transport

// Reality client dialer.  Produces a uTLS ClientHello with a real browser
// fingerprint (Chrome by default), embeds the Reality auth blob in the
// session_id, completes a normal TLS 1.3 handshake with the server, and then
// behaves exactly like TLSTransport (length-prefixed frames over the encrypted
// stream).  The supervpn AES-GCM + FEC layer runs inside, as it does over TLS.
//
// Server authenticity is NOT established by certificate validation here
// (InsecureSkipVerify): the inner supervpn auth (password-derived AES-GCM
// session key) authenticates the server end-to-end, and on the wire the
// certificate is invisible to passive observers because TLS 1.3 encrypts it.

import (
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// RealityClientParams are the dial-time parameters for DialReality.
type RealityClientParams struct {
	Addr        string // server host:port
	SNI         string // fronting server name placed in the ClientHello (e.g. "www.microsoft.com")
	PublicKey   string // base64 X25519 server Reality public key
	ShortID     string // shortID identifier (≤8 bytes)
	Fingerprint string // "chrome" (default), "firefox", "safari", "edge", "ios", "random"
}

// RealityTransport is a Reality channel presented as a length-prefixed frame
// transport, structurally identical to TLSTransport.
type RealityTransport struct {
	*TCPTransport
	conn *utls.UConn
}

// Mode returns "reality".
func (t *RealityTransport) Mode() string { return "reality" }

// Close closes the underlying uTLS connection.
func (t *RealityTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return t.TCPTransport.Close()
}

func fingerprintID(name string) utls.ClientHelloID {
	switch name {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "random":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

// DialReality connects to a Reality server and returns a ready transport.
func DialReality(ctx context.Context, p RealityClientParams) (*RealityTransport, error) {
	serverPub, err := DecodeRealityPublicKey(p.PublicKey)
	if err != nil {
		return nil, err
	}
	shortID := ParseShortID(p.ShortID)

	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.Addr)
	if err != nil {
		return nil, fmt.Errorf("reality: dial %s: %w", p.Addr, err)
	}
	enableKeepalive(rawConn)

	// Apply the handshake deadline derived from ctx (best-effort).
	if dl, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(dl)
	} else {
		_ = rawConn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	ucfg := &utls.Config{
		ServerName:         p.SNI,
		InsecureSkipVerify: true, // inner supervpn auth authenticates the server
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
	}
	uconn := utls.UClient(rawConn, ucfg, fingerprintID(p.Fingerprint))

	if err := uconn.BuildHandshakeState(); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("reality: build handshake: %w", err)
	}

	ks := uconn.HandshakeState.State13.KeyShareKeys
	if ks == nil || ks.Ecdhe == nil {
		uconn.Close()
		return nil, fmt.Errorf("reality: fingerprint %q offers no X25519 key share", p.Fingerprint)
	}
	shared, err := ks.Ecdhe.ECDH(serverPub)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("reality: ECDH: %w", err)
	}

	random := uconn.HandshakeState.Hello.Random
	if len(random) < 12 {
		uconn.Close()
		return nil, fmt.Errorf("reality: short ClientHello random")
	}
	sessionID, err := sealRealityAuth(shared, random, shortID, time.Now().Unix())
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("reality: seal auth: %w", err)
	}
	uconn.HandshakeState.Hello.SessionId = sessionID
	if err := uconn.MarshalClientHello(); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("reality: marshal ClientHello: %w", err)
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("reality: handshake %s: %w", p.Addr, err)
	}
	_ = rawConn.SetDeadline(time.Time{}) // clear for normal operation

	return &RealityTransport{
		TCPTransport: WrapTCP(uconn),
		conn:         uconn,
	}, nil
}
