package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const tcpMaxFrame = 65535

// streamWriteTimeout bounds a single blocking Write to a stream peer. A healthy
// peer accepts a frame into its socket buffer immediately; a peer whose window
// stays shut this long is effectively dead. Without this bound, a stalled
// TLS/Reality destination blocks the hub's forward path (which the server holds
// the per-session order lock across), so one dead peer could freeze a session.
const streamWriteTimeout = 30 * time.Second

// TCPTransport wraps a single TCP connection with length-prefixed framing.
// Frame on wire: [length: 2 big-endian][data: length bytes]
// mu serialises Send: the hub goroutine and recv loop may call Send concurrently,
// and two separate Write calls would interleave their bytes, corrupting the stream.
type TCPTransport struct {
	conn net.Conn
	mu   sync.Mutex
}

// DialTCP connects to a TCP server at addr and returns a TCPTransport.
func DialTCP(addr string) (*TCPTransport, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/tcp: dial %s: %w", addr, err)
	}
	enableKeepalive(conn)
	return &TCPTransport{conn: conn}, nil
}

// WrapTCP wraps an existing net.Conn (e.g. from net.Accept) as a TCPTransport.
func WrapTCP(conn net.Conn) *TCPTransport {
	return &TCPTransport{conn: conn}
}

// Send writes a length-prefixed frame to the TCP connection.
// Single Write call keeps header and body in one TLS record and is safe for
// concurrent callers (hub goroutine + recv loop both write to the same conn).
func (t *TCPTransport) Send(f Frame) error {
	if len(f.Data) > tcpMaxFrame {
		return fmt.Errorf("transport/tcp: frame too large (%d)", len(f.Data))
	}
	buf := make([]byte, 2+len(f.Data))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(f.Data)))
	copy(buf[2:], f.Data)
	t.mu.Lock()
	_ = t.conn.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	_, err := t.conn.Write(buf)
	_ = t.conn.SetWriteDeadline(time.Time{})
	t.mu.Unlock()
	return err
}

// Recv reads one length-prefixed frame from the TCP connection.
// It respects ctx cancellation by closing the connection when the context is done.
func (t *TCPTransport) Recv(ctx context.Context) (Frame, error) {
	// Honour context cancellation: when ctx is done, unblock the blocking Read
	// by closing the connection in a separate goroutine.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			t.conn.Close()
		case <-done:
		}
	}()

	// read 2-byte length header
	var hdr [2]byte
	if _, err := io.ReadFull(t.conn, hdr[:]); err != nil {
		if ctx.Err() != nil {
			return Frame{}, ctx.Err()
		}
		return Frame{}, fmt.Errorf("transport/tcp: read header: %w", err)
	}
	length := binary.BigEndian.Uint16(hdr[:])
	if length == 0 {
		return Frame{Data: nil, Addr: t.conn.RemoteAddr()}, nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(t.conn, buf); err != nil {
		if ctx.Err() != nil {
			return Frame{}, ctx.Err()
		}
		return Frame{}, fmt.Errorf("transport/tcp: read body: %w", err)
	}
	return Frame{Data: buf, Addr: t.conn.RemoteAddr()}, nil
}

// Mode returns "tcp".
func (t *TCPTransport) Mode() string { return "tcp" }

// Close closes the underlying TCP connection.
func (t *TCPTransport) Close() error { return t.conn.Close() }
