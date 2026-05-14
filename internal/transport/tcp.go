package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const tcpMaxFrame = 65535

// TCPTransport wraps a single TCP connection with length-prefixed framing.
// Frame on wire: [length: 2 big-endian][data: length bytes]
type TCPTransport struct {
	conn net.Conn
}

// DialTCP connects to a TCP server at addr and returns a TCPTransport.
func DialTCP(addr string) (*TCPTransport, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/tcp: dial %s: %w", addr, err)
	}
	return &TCPTransport{conn: conn}, nil
}

// WrapTCP wraps an existing net.Conn (e.g. from net.Accept) as a TCPTransport.
func WrapTCP(conn net.Conn) *TCPTransport {
	return &TCPTransport{conn: conn}
}

// Send writes a length-prefixed frame to the TCP connection.
func (t *TCPTransport) Send(f Frame) error {
	if len(f.Data) > tcpMaxFrame {
		return fmt.Errorf("transport/tcp: frame too large (%d)", len(f.Data))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(f.Data)))
	if _, err := t.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Data) == 0 {
		return nil
	}
	_, err := t.conn.Write(f.Data)
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
