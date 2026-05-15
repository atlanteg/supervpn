//go:build darwin

package main

import (
	"log"

	"github.com/atlanteg/supervpn/internal/config"
)

func bridgeSetupHint(_ config.BridgeConfig) {
	log.Printf("bridge mode: BPF bound to physical NIC — no extra setup required (run as root)")
}
