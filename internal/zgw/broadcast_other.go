//go:build !windows

package zgw

import "net"

// enableBroadcast is a no-op on non-Windows platforms where the kernel
// permits sending to broadcast addresses without an explicit socket option.
func enableBroadcast(_ *net.UDPConn) {}
