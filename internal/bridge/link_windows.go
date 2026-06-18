//go:build windows

package bridge

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const ifOperStatusUp = 1 // IF_OPER_STATUS.IfOperStatusUp

// ifaceHasLink reports whether the adapter with the given friendly name (which
// is what net.Interface.Name carries on Windows) is operationally up — i.e.
// media-connected. net.FlagUp only reflects the administrative state, so a
// cable-less Ethernet NIC (which Windows still assigns a 169.254 APIPA address)
// would otherwise be selected for bridging and fail to send raw L2 frames.
//
// Fails open: on any query error it returns true so this extra check can never
// break interface detection.
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
			return a.OperStatus == ifOperStatusUp
		}
	}
	return true
}
