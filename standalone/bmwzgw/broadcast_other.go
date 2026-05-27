//go:build !windows

package bmwzgw

import "net"

func openRecvConn(port int) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{Port: port})
}

func openSendConn(localIP string) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(localIP), Port: 0})
}

// enableBroadcast is a no-op on non-Windows platforms.
func enableBroadcast(_ *net.UDPConn) {}
