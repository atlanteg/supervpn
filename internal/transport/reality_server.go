package transport

// Reality server side.  Peeks the incoming ClientHello, runs the Reality auth
// check, and either:
//
//   - completes a normal TLS 1.3 handshake (authorized client) and returns a
//     frame transport identical to the TLS path, or
//   - transparently splices the raw TCP connection to the real dest site
//     (prober / invalid auth), replaying the bytes already consumed so the
//     prober sees a genuine TLS server with a valid certificate.
//
// Server-side uses only the standard library; uTLS is a client-only concern.

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// RealityServerParams is the runtime configuration for the Reality listener.
type RealityServerParams struct {
	priv       *ecdh.PrivateKey
	dest       string // real site to proxy probers to, e.g. "www.microsoft.com:443"
	shortIDs   [][realityShortIDLen]byte
	timeWindow time.Duration
	tlsConfig  *tls.Config
}

// BuildRealityServerParams assembles the runtime params from config primitives.
// certFile/keyFile may be empty to use a generated self-signed certificate.
func BuildRealityServerParams(privKeyB64, dest string, shortIDs []string, timeWindowSec int, certFile, keyFile string) (RealityServerParams, error) {
	var p RealityServerParams
	priv, err := DecodeRealityPrivateKey(privKeyB64)
	if err != nil {
		return p, err
	}
	if dest == "" {
		return p, fmt.Errorf("reality: dest is required (real fallback site, e.g. \"www.microsoft.com:443\")")
	}
	if _, _, err := net.SplitHostPort(dest); err != nil {
		return p, fmt.Errorf("reality: dest %q must be host:port: %w", dest, err)
	}
	tlsCfg, err := NewServerTLSConfig(certFile, keyFile)
	if err != nil {
		return p, err
	}
	if timeWindowSec <= 0 {
		timeWindowSec = realityTimeWindowDefault
	}
	p.priv = priv
	p.dest = dest
	p.timeWindow = time.Duration(timeWindowSec) * time.Second
	p.tlsConfig = tlsCfg
	for _, s := range shortIDs {
		p.shortIDs = append(p.shortIDs, ParseShortID(s))
	}
	if len(p.shortIDs) == 0 {
		// An empty list would reject every client; default to a single
		// all-zero shortID so a minimal config (no short_ids) still works.
		p.shortIDs = append(p.shortIDs, [realityShortIDLen]byte{})
	}
	return p, nil
}

// PublicKeyBase64 returns the base64 X25519 public key clients must configure.
func (p RealityServerParams) PublicKeyBase64() string {
	return EncodeRealityKey(p.priv.PublicKey().Bytes())
}

// AcceptReality handles one freshly-accepted raw TCP connection.
//
// When the client authenticates, it returns a ready frame transport and
// authorized=true.  When the client is a prober (or anything unrecognised), it
// splices the connection to the dest site and returns authorized=false with a
// nil transport — the caller should simply return.  The splice runs inline and
// blocks until the proxied connection closes, so call this from a per-connection
// goroutine.
func AcceptReality(ctx context.Context, raw net.Conn, p RealityServerParams) (tr Transport, authorized bool, err error) {
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))

	record, consumed, perr := readFirstTLSRecord(raw)
	if perr != nil {
		raw.Close()
		return nil, false, perr
	}

	ch, ok := parseClientHelloRecord(record)
	if !ok || ch.x25519Pub == nil {
		realityFallback(raw, p.dest, consumed)
		return nil, false, nil
	}

	if !p.authenticate(ch) {
		realityFallback(raw, p.dest, consumed)
		return nil, false, nil
	}

	// Authorized: replay the buffered ClientHello into a stdlib TLS server.
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	pc := &prefixConn{Conn: raw, prefix: consumed}
	tlsConn := tls.Server(pc, p.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, false, fmt.Errorf("reality: server handshake: %w", err)
	}
	_ = raw.SetReadDeadline(time.Time{})
	return &RealityTransport{TCPTransport: WrapTCP(tlsConn)}, true, nil
}

func (p RealityServerParams) authenticate(ch parsedClientHello) bool {
	clientPub, err := ecdh.X25519().NewPublicKey(ch.x25519Pub)
	if err != nil {
		return false
	}
	shared, err := p.priv.ECDH(clientPub)
	if err != nil {
		return false
	}
	shortID, t, ok := openRealityAuth(shared, ch.random, ch.sessionID)
	if !ok {
		return false
	}
	if !shortIDAllowed(shortID, p.shortIDs) {
		return false
	}
	skew := time.Now().Unix() - t
	if skew < 0 {
		skew = -skew
	}
	return time.Duration(skew)*time.Second <= p.timeWindow
}

// readFirstTLSRecord reads the first TLS record from conn.  It returns the full
// record bytes (for parsing) and the same bytes as "consumed" (for replay on
// fallback).  If the first byte is not a handshake record it returns only the
// bytes read so far so the fallback can still replay them verbatim.
func readFirstTLSRecord(conn net.Conn) (record, consumed []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, hdr[:], fmt.Errorf("reality: read record header: %w", err)
	}
	if hdr[0] != 0x16 { // not a handshake record — let the caller fall back
		return nil, hdr[:], nil
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n == 0 || n > 16384 {
		return nil, hdr[:], nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, hdr[:], fmt.Errorf("reality: read record body: %w", err)
	}
	full := make([]byte, 5+n)
	copy(full, hdr[:])
	copy(full[5:], body)
	return full, full, nil
}

// realityFallback proxies client to the real dest site, replaying the bytes
// already read from the client, so active probes see a genuine TLS endpoint.
func realityFallback(client net.Conn, dest string, consumed []byte) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Time{})
	up, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if len(consumed) > 0 {
		if _, err := up.Write(consumed); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// prefixConn is a net.Conn whose Read returns buffered prefix bytes before
// delegating to the underlying connection.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
