//go:build windows

package tun

import (
	"context"
	"fmt"
	"log"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	// CTL_CODE(FILE_DEVICE_NETWORK=0x12, func, METHOD_BUFFERED=0, FILE_READ_ACCESS|FILE_WRITE_ACCESS=3)
	// Values from Windows WDK ndisuio.h — func numbers are 0,1,2 (NOT 0x200+).
	ioctlNDISUIOBindWait   = 0x0012C000 // func=0: wait for adapter bindings to settle
	ioctlNDISUIOOpenDevice = 0x0012C008 // func=2: bind handle to a specific adapter
	ioctlNDISUIOSetOID     = 0x0012C010 // func=4: set OID value on the bound adapter

	// OID_GEN_CURRENT_PACKET_FILTER (0x0001010E) bitmask values.
	ndisPacketTypeDirected   = 0x0001
	ndisPacketTypeMulticast  = 0x0004
	ndisPacketTypeAllMulticast = 0x0008
	ndisPacketTypeBroadcast  = 0x0010
	ndisPacketTypePromiscuous = 0x0020
)

type ndisuioFramer struct {
	handle windows.Handle
	ifName string
}

func openNDISUIOFramer(nicName string) (*ndisuioFramer, error) {
	devPath, _ := windows.UTF16PtrFromString(`\\.\Ndisuio`)
	h, err := windows.CreateFile(devPath,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED,
		0)
	if err != nil {
		log.Printf("bridge/ndisuio: open \\.\\ Ndisuio failed: %v", err)
		return nil, fmt.Errorf("ndisuio: open driver: %w", err)
	}
	log.Printf("bridge/ndisuio: driver handle open")

	guid, err := adapterGUIDByFriendlyName(nicName)
	if err != nil {
		windows.CloseHandle(h)
		log.Printf("bridge/ndisuio: GUID lookup for %q failed: %v", nicName, err)
		return nil, fmt.Errorf("ndisuio: %w", err)
	}
	log.Printf("bridge/ndisuio: adapter %q → GUID %s", nicName, guid)

	// Adapter device name as UTF-16LE bytes (no null terminator in the IOCTL buffer).
	adapterPath := `\Device\` + guid
	u16 := utf16.Encode([]rune(adapterPath))
	buf := make([]byte, len(u16)*2)
	for i, c := range u16 {
		buf[i*2] = byte(c)
		buf[i*2+1] = byte(c >> 8)
	}

	var ret uint32
	// BIND_WAIT waits for NDISUIO to finish binding to all adapters after boot.
	// Ignore errors here — if it times out or fails we still attempt OPEN_DEVICE.
	bindWaitErr := windows.DeviceIoControl(h, ioctlNDISUIOBindWait, nil, 0, nil, 0, &ret, nil)
	log.Printf("bridge/ndisuio: BIND_WAIT result: %v", bindWaitErr)

	if err := windows.DeviceIoControl(h, ioctlNDISUIOOpenDevice,
		&buf[0], uint32(len(buf)),
		nil, 0, &ret, nil); err != nil {
		windows.CloseHandle(h)
		log.Printf("bridge/ndisuio: OPEN_DEVICE for %q failed: %v", adapterPath, err)
		return nil, fmt.Errorf("ndisuio: bind to %q: %w", adapterPath, err)
	}

	log.Printf("bridge/ndisuio: bound to %q (%s)", nicName, adapterPath)

	// Enable promiscuous mode so we capture unicast frames destined for remote
	// VPN client MACs, not just frames addressed to this NIC's own MAC.
	if err := ndisuioSetPromiscuous(h); err != nil {
		log.Printf("bridge/ndisuio: WARNING: cannot set promiscuous mode: %v — unicast frames for remote VPN clients may be missed", err)
	} else {
		log.Printf("bridge/ndisuio: promiscuous mode enabled")
	}

	return &ndisuioFramer{handle: h, ifName: nicName}, nil
}

// ndisuioSetPromiscuous sends IOCTL_NDISUIO_SET_OID with OID_GEN_CURRENT_PACKET_FILTER
// set to PROMISCUOUS | DIRECTED | MULTICAST | BROADCAST.
func ndisuioSetPromiscuous(h windows.Handle) error {
	// Payload layout (little-endian): OID uint32 + filter uint32
	oid := uint32(0x0001010E) // OID_GEN_CURRENT_PACKET_FILTER
	filter := uint32(ndisPacketTypePromiscuous | ndisPacketTypeDirected |
		ndisPacketTypeMulticast | ndisPacketTypeAllMulticast | ndisPacketTypeBroadcast)
	var buf [8]byte
	buf[0], buf[1], buf[2], buf[3] = byte(oid), byte(oid>>8), byte(oid>>16), byte(oid>>24)
	buf[4], buf[5], buf[6], buf[7] = byte(filter), byte(filter>>8), byte(filter>>16), byte(filter>>24)
	var ret uint32
	return windows.DeviceIoControl(h, ioctlNDISUIOSetOID,
		&buf[0], uint32(len(buf)), nil, 0, &ret, nil)
}

func (f *ndisuioFramer) ReadFrame(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 65536)
	ol := new(windows.Overlapped)
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("ndisuio: create event: %w", err)
	}
	ol.HEvent = ev
	defer windows.CloseHandle(ev)

	var n uint32
	err = windows.ReadFile(f.handle, buf, &n, ol)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return nil, fmt.Errorf("ndisuio: read: %w", err)
	}

	for {
		r, _ := windows.WaitForSingleObject(ev, 100) // 100 ms poll
		if r == windows.WAIT_OBJECT_0 {
			break
		}
		select {
		case <-ctx.Done():
			windows.CancelIoEx(f.handle, ol)
			return nil, ctx.Err()
		default:
		}
	}

	if err := windows.GetOverlappedResult(f.handle, ol, &n, false); err != nil {
		return nil, fmt.Errorf("ndisuio: read result: %w", err)
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

func (f *ndisuioFramer) WriteFrame(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	ol := new(windows.Overlapped)
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("ndisuio: create event: %w", err)
	}
	ol.HEvent = ev
	defer windows.CloseHandle(ev)

	var n uint32
	err = windows.WriteFile(f.handle, frame, &n, ol)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return fmt.Errorf("ndisuio: write: %w", err)
	}
	windows.WaitForSingleObject(ev, windows.INFINITE)
	return nil
}

func (f *ndisuioFramer) Close() error   { return windows.CloseHandle(f.handle) }
func (f *ndisuioFramer) IfName() string { return f.ifName }
