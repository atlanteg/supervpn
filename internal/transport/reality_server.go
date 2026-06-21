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
	"sync"
	"time"
)

// RealityServerParams is the runtime configuration for the Reality listener.
type RealityServerParams struct {
	privs       []*ecdh.PrivateKey // one or more Reality private keys (pool); tried in order
	dest        string             // real site to proxy probers to, e.g. "www.microsoft.com:443"
	serverNames []string           // allowed SNIs; empty = accept any
	shortIDs    [][realityShortIDLen]byte
	timeWindow  time.Duration
	tlsConfig   *tls.Config
	replay      *replayCache // anti-replay: rejects re-sent ClientHellos
}

// BuildRealityServerParams assembles the runtime params from config primitives.
// privKeysB64 is one or more base64 X25519 private keys: a single key for a
// classic deployment, or a pool that matches the public keys embedded in the
// client. The server tries each key when authenticating a ClientHello.
// certFile/keyFile may be empty to use a generated self-signed certificate.
// serverNames, when non-empty, restricts which SNI an authorized client may
// send (it should be coherent with dest); any other SNI is treated as a prober.
func BuildRealityServerParams(privKeysB64 []string, dest string, serverNames, shortIDs []string, timeWindowSec int, certFile, keyFile string) (RealityServerParams, error) {
	var p RealityServerParams
	if len(privKeysB64) == 0 {
		return p, fmt.Errorf("reality: no private key configured (set private_key or private_keys)")
	}
	for _, s := range privKeysB64 {
		priv, err := DecodeRealityPrivateKey(s)
		if err != nil {
			return p, err
		}
		p.privs = append(p.privs, priv)
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
	p.dest = dest
	p.serverNames = serverNames
	p.timeWindow = time.Duration(timeWindowSec) * time.Second
	p.tlsConfig = tlsCfg
	// Remember auth blobs for 2× the time window: anything older is rejected by
	// the timestamp check anyway, so the cache never needs a longer memory.
	p.replay = newReplayCache(int64(2 * timeWindowSec))
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

// replayCache rejects ClientHellos whose auth blob (session_id) was already
// seen within the TTL.  A genuine client generates a fresh random ephemeral and
// nonce on every connection, so its session_id is unique; an active prober that
// captures and re-sends a recorded ClientHello reuses the exact session_id and
// is detected here — it then falls through to the dest fallback, making a replay
// indistinguishable from any other probe.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]int64 // session_id → unix time first seen
	ttl  int64            // seconds
}

func newReplayCache(ttlSec int64) *replayCache {
	return &replayCache{seen: make(map[string]int64), ttl: ttlSec}
}

// fresh records key and returns true if it was not seen within the TTL.
func (c *replayCache) fresh(key []byte, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, t := range c.seen {
		if now-t > c.ttl {
			delete(c.seen, k)
		}
	}
	k := string(key)
	if t, ok := c.seen[k]; ok && now-t <= c.ttl {
		return false
	}
	c.seen[k] = now
	return true
}

// PublicKeyBase64 returns the base64 X25519 public key for the first configured
// private key (for logging). With a pool, only the first is shown.
func (p RealityServerParams) PublicKeyBase64() string {
	if len(p.privs) == 0 {
		return ""
	}
	return EncodeRealityKey(p.privs[0].PublicKey().Bytes())
}

// PoolSize returns the number of configured Reality private keys.
func (p RealityServerParams) PoolSize() int { return len(p.privs) }

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
	// SNI coherence: when an allowlist is configured, the client must use one of
	// the expected server names (kept consistent with dest). Any other SNI is a
	// prober → fallback.
	if len(p.serverNames) > 0 && !sniAllowed(ch.serverName, p.serverNames) {
		return false
	}

	clientPub, err := ecdh.X25519().NewPublicKey(ch.x25519Pub)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	// Try each private key in the pool: the client picked one public key, and we
	// don't know which, so we find the matching private key by trial decryption.
	for _, priv := range p.privs {
		shared, err := priv.ECDH(clientPub)
		if err != nil {
			continue
		}
		shortID, t, ok := openRealityAuth(shared, ch.random, ch.sessionID)
		if !ok {
			continue // wrong key for this client — try next
		}
		if !shortIDAllowed(shortID, p.shortIDs) {
			return false
		}
		skew := now - t
		if skew < 0 {
			skew = -skew
		}
		if time.Duration(skew)*time.Second > p.timeWindow {
			return false
		}
		// Anti-replay: a re-sent ClientHello carries the same auth blob.
		return p.replay.fresh(ch.sessionID, now)
	}
	return false
}

func sniAllowed(sni string, allowed []string) bool {
	for _, a := range allowed {
		if sni == a {
			return true
		}
	}
	return false
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
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Half-close: propagate EOF so the other direction also finishes, rather
		// than returning after just one side and letting the deferred Close cut
		// the proxy off mid-stream — that truncated the dest's response to a
		// prober (a tell for a censor, and the source of the flaky test).
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, client)
	go pipe(client, up)
	<-done
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
