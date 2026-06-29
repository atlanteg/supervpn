//go:build darwin

package clientadapter

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// autoAssignLinkLocal assigns 169.254.100.1/16 to the utun interface when the
// user has not explicitly configured TunIP. Without an IP on utun, macOS does
// not add a route for 169.254.0.0/16 via utun, so all link-local traffic goes
// via the physical NIC (en7) instead of the VPN hub. Consequences:
//   - ZGW discovery probes never reach the remote BMW.
//   - Pings to remote 169.254 peers fail (routed to physical wire, not hub).
//   - Detection only flickers when BMW broadcasts spontaneously (passive rx).
//
// We also delete any competing /16 route (e.g. from en7's APIPA address) so
// the utun route is unambiguous. In direct mode the physical NIC is not
// bridged — its link-local route is unused anyway.
func autoAssignLinkLocal(ifaceName string) error {
	// Remove any existing 169.254.0.0/16 route so utun's route wins.
	exec.Command("route", "delete", "169.254.0.0").Run()

	cmd := exec.Command("ifconfig", ifaceName, "inet", "169.254.100.1", "netmask", "255.255.0.0")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already") {
		return fmt.Errorf("ifconfig %s: %v: %s", ifaceName, err, strings.TrimSpace(string(out)))
	}
	log.Printf("direct mode: %s: auto-assigned 169.254.100.1/16 (override with tun_ip in config)", ifaceName)
	return nil
}
