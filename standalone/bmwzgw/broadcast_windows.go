//go:build windows

package bmwzgw

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// winSockOpts sets SO_REUSEADDR and SO_BROADCAST before the socket is bound.
// SO_REUSEADDR lets us share port 6811 with Remote Enet / ZGW_SEARCH without
// EADDRINUSE.  SO_BROADCAST is required on Windows — without it, WriteToUDP
// to 169.254.255.255 is silently dropped by Winsock.
func winSockOpts(_, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
}

// openRecvConn opens a UDP socket bound to 0.0.0.0:port with SO_REUSEADDR and
// SO_BROADCAST.  Binding to INADDR_ANY catches both unicast ZGW responses and
// broadcast ZGW announcements on port 6811.
func openRecvConn(port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: winSockOpts}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// openSendConn opens a UDP socket bound to localIP:0 with SO_BROADCAST.
// Binding to the specific 169.254.x.x address forces the OS to route the
// outgoing broadcast through the correct interface on multi-homed machines.
func openSendConn(localIP string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: winSockOpts}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(localIP, "0"))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// enableBroadcast sets SO_BROADCAST post-bind on a socket created with the
// plain net.ListenUDP API (used by Discover which bypasses ListenConfig).
func enableBroadcast(conn *net.UDPConn) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
}
