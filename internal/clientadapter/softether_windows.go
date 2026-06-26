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

// DisableSoftEtherAdapters finds every SoftEther VPN Client virtual adapter
// (identified by ComponentId "sun_neo" in the registry) and disables it.
// Called at client startup so SoftEther's adapter does not interfere with
// supervpn's own adapter or the BMW ENET discovery broadcast.
func DisableSoftEtherAdapters() {
	names, err := softEtherAdapterNames()
	if err != nil {
		log.Printf("softether: enumerate: %v", err)
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
		guid, _, _ := sub.GetStringValue("NetCfgInstanceId")
		sub.Close()

		if !strings.EqualFold(compID, "sun_neo") || guid == "" {
			continue
		}
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
