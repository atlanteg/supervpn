//go:build !linux && !windows

package tun

import "fmt"

func openPlatform(name string) (interface{ Close() error }, error) {
	return nil, fmt.Errorf("tun: platform not supported")
}
