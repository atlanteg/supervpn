//go:build windows

package bridge

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// IF_OPER_STATUS values that mean the adapter definitely cannot carry traffic.
// Everything else (Up=1, Testing=3, Unknown=4, Dormant=5) is treated as usable:
// some working NICs — USB-Ethernet, virtual adapters — report Unknown/Dormant
// even when up, so requiring strictly Up wrongly excluded them from bridging.
const (
	ifOperStatusDown           = 2
	ifOperStatusNotPresent     = 6
	ifOperStatusLowerLayerDown = 7
)

// findAdapter returns the IP_ADAPTER_ADDRESSES entry whose friendly name (what
// net.Interface.Name carries on Windows) matches name, or nil if not found / on
// query error.
func findAdapter(name string) *windows.IpAdapterAddresses {
	size := uint32(15000)
	var buf []byte
	ok := false
	for i := 0; i < 4; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			ok = true
			break
		}
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		return nil
	}
	if !ok {
		return nil
	}
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if windows.UTF16PtrToString(a.FriendlyName) == name {
			return a
		}
	}
	return nil
}

// ifaceHasLink reports whether the named adapter can carry traffic. net.FlagUp
// only reflects the administrative state, so a cable-less Ethernet NIC (which
// Windows still assigns a 169.254 APIPA address) would otherwise be selected
// for bridging and fail to send raw L2 frames. Only adapters in a definitively
// down state are excluded. Fails open: on any query error / unrecognised state
// it returns true so this extra check can never wrongly exclude a usable NIC.
func ifaceHasLink(name string) bool {
	a := findAdapter(name)
	if a == nil {
		return true
	}
	switch a.OperStatus {
	case ifOperStatusDown, ifOperStatusNotPresent, ifOperStatusLowerLayerDown:
		return false
	}
	return true
}

// adapterDescription returns the hardware description of the named adapter (e.g.
// "Famatech Radmin VPN Ethernet Adapter"), or "" if unknown. The description is
// stable even when the user renames the network connection.
func adapterDescription(name string) string {
	a := findAdapter(name)
	if a == nil {
		return ""
	}
	return windows.UTF16PtrToString(a.Description)
}
