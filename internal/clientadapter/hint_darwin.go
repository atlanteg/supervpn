//go:build darwin

package clientadapter

import (
	"log"

	"github.com/atlanteg/supervpn/internal/config"
)

func ensureBridge(_ config.BridgeConfig, _, _ string) error {
	log.Printf("bridge mode: BPF bound to physical NIC — no extra setup required (run as root)")
	return nil
}
