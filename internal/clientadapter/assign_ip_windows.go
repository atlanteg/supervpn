//go:build windows

package clientadapter

import (
	"fmt"
	"net"
	"os/exec"
)

// assignAdapterIP assigns the given CIDR address (e.g. "192.168.100.10/24") to
// the named adapter using netsh. Replaces any previously configured IP.
func assignAdapterIP(name, cidr string) error {
	ip, ipnet, err := parseCIDR(cidr)
	if err != nil {
		return err
	}
	mask := net.IP(ipnet.Mask).String()
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+name, "static", ip, mask)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address %s on %s: %v: %s", cidr, name, err, out)
	}
	return nil
}

// parseCIDR accepts "host/prefix" or a bare IP (defaults to /24).
func parseCIDR(cidr string) (string, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// bare IP — assume /24
		parsed := net.ParseIP(cidr)
		if parsed == nil {
			return "", nil, fmt.Errorf("invalid TUN IP %q (use CIDR, e.g. 192.168.100.10/24)", cidr)
		}
		_, ipnet, _ = net.ParseCIDR(cidr + "/24")
		return parsed.String(), ipnet, nil
	}
	return ip.String(), ipnet, nil
}
