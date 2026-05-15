//go:build !darwin && !windows

package main

import "github.com/atlanteg/supervpn/internal/config"

func ensureBridge(_ config.BridgeConfig, _, _ string) error { return nil }
