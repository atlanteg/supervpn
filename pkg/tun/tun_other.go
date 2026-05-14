//go:build !linux && !windows && !darwin

package tun

import (
	"context"
	"fmt"

	"github.com/atlanteg/supervpn/internal/bridge"
)

type unsupportedTUN struct{}

func openPlatform(name string) (*unsupportedTUN, error) {
	return nil, fmt.Errorf("tun: platform not supported")
}

func (u *unsupportedTUN) ReadFrame(_ context.Context) ([]byte, error) {
	return nil, fmt.Errorf("tun: platform not supported")
}

func (u *unsupportedTUN) WriteFrame(_ []byte) error {
	return fmt.Errorf("tun: platform not supported")
}

func (u *unsupportedTUN) Close() error { return nil }

var _ bridge.Framer = (*unsupportedTUN)(nil)
