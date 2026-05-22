package transport

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	udpReadBuf    = 2048
	udpSockBufSz  = 4 * 1024 * 1024 // 4 MiB OS socket buffer — prevents silent drops during burst arrivals
)

// recvBufPool reuses read buffers across Recv calls; one buffer per goroutine
// since Recv is always called from a single dedicated read goroutine per socket.
var recvBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, udpReadBuf)
		return &b
	},
}

type UDPTransport struct {
	conn *net.UDPConn
}

func DialUDP(addr string) (*UDPTransport, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/udp: resolve %s: %w", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("transport/udp: dial: %w", err)
	}
	_ = conn.SetReadBuffer(udpSockBufSz)
	_ = conn.SetWriteBuffer(udpSockBufSz)
	return &UDPTransport{conn: conn}, nil
}

func ListenUDP(addr string) (*UDPTransport, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(udpSockBufSz)
	_ = conn.SetWriteBuffer(udpSockBufSz)
	return &UDPTransport{conn: conn}, nil
}

func (u *UDPTransport) Send(f Frame) error {
	_, err := u.conn.Write(f.Data)
	return err
}

func (u *UDPTransport) Recv(ctx context.Context) (Frame, error) {
	bufPtr := recvBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer recvBufPool.Put(bufPtr)

	_ = u.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		select {
		case <-ctx.Done():
			return Frame{}, ctx.Err()
		default:
		}
		n, addr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				_ = u.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				continue
			}
			return Frame{}, err
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return Frame{Data: out, Addr: addr}, nil
	}
}

func (u *UDPTransport) Mode() string { return "udp" }

func (u *UDPTransport) Close() error { return u.conn.Close() }

// KnockAndDial sends knockCount random-payload UDP packets to addr to prime NAT and
// firewall state, then returns the same connected socket ready for VPN use.
// Using the same socket for knock and auth keeps the 5-tuple (src_ip:src_port →
// dst_ip:dst_port) identical, so the mapping created by the knock packets covers
// all subsequent VPN traffic on that socket.
// If knockCount or knockSize is 0 the function behaves identically to DialUDP.
func KnockAndDial(addr string, knockCount, knockSize int) (*UDPTransport, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/udp: resolve %s: %w", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("transport/udp: dial: %w", err)
	}
	if knockCount > 0 && knockSize > 0 {
		knock := make([]byte, knockSize)
		rand.Read(knock)
		for i := 0; i < knockCount; i++ {
			_, _ = conn.Write(knock) // best-effort; server drops unrecognised frames silently
			time.Sleep(50 * time.Millisecond)
		}
		// Let NAT state settle before the first real frame arrives.
		time.Sleep(100 * time.Millisecond)
	}
	return &UDPTransport{conn: conn}, nil
}
