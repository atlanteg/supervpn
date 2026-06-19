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

// ifaceHasLink reports whether the adapter with the given friendly name (which
// is what net.Interface.Name carries on Windows) can carry traffic. net.FlagUp
// only reflects the administrative state, so a cable-less Ethernet NIC (which
// Windows still assigns a 169.254 APIPA address) would otherwise be selected
// for bridging and fail to send raw L2 frames. Only adapters in a definitively
// down state are excluded.
//
// Fails open: on any query error, or an unrecognised state, it returns true so
// this extra check can never wrongly exclude a usable adapter.
func ifaceHasLink(name string) bool {
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
		return true
	}
	if !ok {
		return true
	}
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if windows.UTF16PtrToString(a.FriendlyName) == name {
			switch a.OperStatus {
			case ifOperStatusDown, ifOperStatusNotPresent, ifOperStatusLowerLayerDown:
				return false
			}
			return true
		}
	}
	return true
}
