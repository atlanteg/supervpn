//go:build windows

package tun

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// adapterGUIDByFriendlyName returns the NetCfgInstanceId GUID for any network adapter
// by scanning HKLM\SYSTEM\CurrentControlSet\Control\Network\{4D36E972...}\{GUID}\Connection\Name.
func adapterGUIDByFriendlyName(name string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`,
		registry.READ)
	if err != nil {
		return "", fmt.Errorf("open network key: %w", err)
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	for _, guid := range subkeys {
		conn, err := registry.OpenKey(k, guid+`\Connection`, registry.READ)
		if err != nil {
			continue
		}
		n, _, err := conn.GetStringValue("Name")
		conn.Close()
		if err == nil && strings.EqualFold(n, name) {
			return guid, nil
		}
	}
	return "", fmt.Errorf("adapter %q not found in registry", name)
}
