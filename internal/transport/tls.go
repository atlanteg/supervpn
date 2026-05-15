package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// TLSTransport wraps TCPTransport with TLS 1.3.
// On the wire: same length-prefixed frames as TCPTransport, just inside TLS.
type TLSTransport struct {
	*TCPTransport
	conn *tls.Conn
}

// DialTLS connects to addr with TLS. sni is sent in the ClientHello (SNI field).
// Certificate verification is skipped — the server uses a self-signed cert.
// TLS 1.3 is enforced. The TCP dial and TLS handshake both respect ctx cancellation.
func DialTLS(ctx context.Context, addr, sni string) (*TLSTransport, error) {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // server uses self-signed cert
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	d := tls.Dialer{Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/tls: dial %s: %w", addr, err)
	}
	tlsConn := conn.(*tls.Conn)
	return &TLSTransport{
		TCPTransport: WrapTCP(tlsConn),
		conn:         tlsConn,
	}, nil
}

// ListenTLS creates a TLS listener on addr using the provided tls.Config.
// Use NewServerTLSConfig to build the config (loads cert or generates self-signed).
func ListenTLS(addr string, cfg *tls.Config) (net.Listener, error) {
	l, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("transport/tls: listen %s: %w", addr, err)
	}
	return l, nil
}

// AcceptTLS wraps an accepted net.Conn (from ListenTLS) into a TLSTransport
// and performs the TLS handshake immediately with a 10-second deadline.
// Returning the error here (instead of letting it surface on first Recv) gives
// a clear diagnostic log entry rather than a confusing read error.
func AcceptTLS(conn net.Conn) (*TLSTransport, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return &TLSTransport{TCPTransport: WrapTCP(conn)}, nil
	}
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("transport/tls: handshake: %w", err)
	}
	tlsConn.SetDeadline(time.Time{}) // clear deadline for normal operation
	return &TLSTransport{TCPTransport: WrapTCP(tlsConn), conn: tlsConn}, nil
}

// Mode returns "tls".
func (t *TLSTransport) Mode() string { return "tls" }

// Close closes the underlying TLS connection.
func (t *TLSTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return t.TCPTransport.Close()
}

// NewServerTLSConfig builds a *tls.Config for the server.
// If certFile and keyFile are non-empty, loads them from disk.
// Otherwise generates a fresh self-signed ECDSA P-256 cert valid for 10 years.
// TLS 1.3 only.
func NewServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("transport/tls: load cert: %w", err)
		}
	} else {
		cert, err = generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("transport/tls: generate cert: %w", err)
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

// generateSelfSignedCert generates a self-signed ECDSA P-256 certificate.
// The cert has no SANs and an empty subject — intentionally generic.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}),
	)
}
