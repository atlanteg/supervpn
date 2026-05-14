package transport

import (
	"context"
	"fmt"
	"net"
	"time"
)

const udpReadBuf = 2048

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
	return &UDPTransport{conn: conn}, nil
}

func (u *UDPTransport) Send(f Frame) error {
	_, err := u.conn.Write(f.Data)
	return err
}

func (u *UDPTransport) Recv(ctx context.Context) (Frame, error) {
	buf := make([]byte, udpReadBuf)
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
