//go:build !linux && !windows && !darwin

package tun

import (
	"fmt"

	"github.com/atlanteg/supervpn/internal/bridge"
)

// OpenBridge is not supported on this platform.
func OpenBridge(_ string) (bridge.Framer, error) {
	return nil, fmt.Errorf("tun: OpenBridge is not supported on this platform")
}
