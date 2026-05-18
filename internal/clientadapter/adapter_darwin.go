//go:build darwin

package clientadapter

import (
	"fmt"
	"log"
	"strings"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

func bridgeName(_, detectedNIC string) string { return detectedNIC }

func openDirectFramer(_ config.BridgeConfig, tunName string) (bridge.Framer, string, error) {
	f, err := pkgtun.Open(tunName)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			err = fmt.Errorf("%w — на macOS нужен root: запустите с sudo", err)
		}
		return nil, "", err
	}
	return f, tunName, nil
}

func openPlatformBridge(bc config.BridgeConfig, detected bridge.Interface, adapterName string) (bridge.Framer, error) {
	if err := ensureBridge(bc, detected.Name, adapterName); err != nil {
		log.Printf("bridge: setup warning: %v", err)
	}
	return pkgtun.OpenBridge(adapterName)
}
