//go:build windows

package clientadapter

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const netAdapterClassSE = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`

// isSoftEtherAdapter returns true for a SoftEther VPN Client virtual adapter.
// Any one signal is sufficient:
//   - ComponentId starts with "NeoAdapter_"  (e.g. "NeoAdapter_VPN", "NeoAdapter_VPN2")
//   - ComponentId == "sun_neo"               (older SoftEther versions)
//   - DriverDesc starts with "VPN Client Adapter"
func isSoftEtherAdapter(compID, driverDesc string) bool {
	c := strings.ToLower(compID)
	return strings.HasPrefix(c, "neoadapter_") ||
		c == "sun_neo" ||
		strings.HasPrefix(strings.ToLower(driverDesc), "vpn client adapter")
}

// DisableSoftEtherAdapters finds every SoftEther VPN Client virtual adapter
// and disables it via netsh. Called at startup after UAC elevation.
func DisableSoftEtherAdapters() {
	names, err := softEtherAdapterNames()
	if err != nil {
		log.Printf("softether: enumerate: %v", err)
		return
	}
	if len(names) == 0 {
		log.Printf("softether: no adapters found")
		return
	}
	for _, name := range names {
		if err := netshDisableAdapter(name); err != nil {
			log.Printf("softether: disable %q: %v", name, err)
		} else {
			log.Printf("softether: disabled adapter %q", name)
		}
	}
}

func softEtherAdapterNames() ([]string, error) {
	cls, err := registry.OpenKey(registry.LOCAL_MACHINE, netAdapterClassSE, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("open adapter class key: %w", err)
	}
	defer cls.Close()

	subkeys, err := cls.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, sk := range subkeys {
		sub, err := registry.OpenKey(cls, sk, registry.READ)
		if err != nil {
			continue
		}
		compID, _, _ := sub.GetStringValue("ComponentId")
		desc, _, _ := sub.GetStringValue("DriverDesc")
		guid, _, _ := sub.GetStringValue("NetCfgInstanceId")
		sub.Close()

		if guid == "" {
			continue
		}
		if !isSoftEtherAdapter(compID, desc) {
			continue
		}
		log.Printf("softether: found adapter guid=%s compID=%q desc=%q", guid, compID, desc)

		name, err := seAdapterName(guid)
		if err != nil {
			log.Printf("softether: get name for %s: %v", guid, err)
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

func seAdapterName(guid string) (string, error) {
	path := `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\` + guid + `\Connection`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return "", err
	}
	defer k.Close()
	name, _, err := k.GetStringValue("Name")
	return name, err
}

func netshDisableAdapter(name string) error {
	cmd := exec.Command("netsh", "interface", "set", "interface", name, "admin=disabled")
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
