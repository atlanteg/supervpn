//go:build !windows

package clientadapter

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

func assignAdapterIP(name, cidr string) error {
	ip, ipnet, err := parseCIDR(cidr)
	if err != nil {
		return err
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		mask := net.IP(ipnet.Mask).String()
		cmd = exec.Command("ifconfig", name, "inet", ip, "netmask", mask)
	} else {
		ones, _ := ipnet.Mask.Size()
		cmd = exec.Command("ip", "addr", "add",
			fmt.Sprintf("%s/%d", ip, ones), "dev", name)
	}

	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already") {
		return fmt.Errorf("assign IP %s to %s: %v: %s", cidr, name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func parseCIDR(cidr string) (string, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		parsed := net.ParseIP(cidr)
		if parsed == nil {
			return "", nil, fmt.Errorf("invalid TUN IP %q (use CIDR, e.g. 192.168.100.10/24)", cidr)
		}
		_, ipnet, _ = net.ParseCIDR(cidr + "/24")
		return parsed.String(), ipnet, nil
	}
	return ip.String(), ipnet, nil
}
