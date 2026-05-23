//go:build !windows

package zgw

import (
	"fmt"
	"net"
)

func openRecvConn(port int) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{Port: port})
}

func openSendConn(localIP string) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(localIP), Port: 0})
}

// enableBroadcast is a no-op on non-Windows platforms.
func enableBroadcast(_ *net.UDPConn) {}

// Silence "declared and not used" for fmt if only used on Windows.
var _ = fmt.Sprintf
