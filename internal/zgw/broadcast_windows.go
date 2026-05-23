//go:build windows

package zgw

import (
	"net"
	"syscall"
)

// enableBroadcast sets SO_BROADCAST on the UDP socket.
// On Windows this is mandatory — without it, WriteToUDP to the link-local
// broadcast address 169.254.255.255 is silently dropped by Winsock even
// though no error is returned by Write.  Remote Enet and ZGW_SEARCH set
// this flag explicitly via the Win32 socket API; we replicate that here.
func enableBroadcast(conn *net.UDPConn) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
}
