//go:build !windows

package tun

import (
	"fmt"

	"github.com/atlanteg/supervpn/internal/bridge"
)

// OpenTAP is a Windows-only feature. On other platforms bridge mode uses the
// platform's native TUN device (utun on macOS, TAP on Linux).
func OpenTAP(_ string) (bridge.Framer, error) {
	return nil, fmt.Errorf("tap: OpenTAP is only supported on Windows")
}
