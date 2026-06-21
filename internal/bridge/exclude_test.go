package bridge

import "testing"

func TestIsExcludedFromBridge(t *testing.T) {
	excluded := []string{"Radmin VPN", "radmin vpn", "Network 5 (Radmin)", "FAMATECH adapter", "Famatech Radmin VPN Ethernet Adapter"}
	for _, n := range excluded {
		if !IsExcludedFromBridge(n) {
			t.Errorf("expected %q to be excluded", n)
		}
	}
	allowed := []string{"Ethernet", "Ethernet 2", "vEthernet (Default Switch)", "Wi-Fi", "supervpn"}
	for _, n := range allowed {
		if IsExcludedFromBridge(n) {
			t.Errorf("did not expect %q to be excluded", n)
		}
	}
}
