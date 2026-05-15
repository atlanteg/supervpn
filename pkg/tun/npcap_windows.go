//go:build windows

package tun

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pcapPkthdr matches struct pcap_pkthdr layout (timeval + caplen + len).
type pcapPkthdr struct {
	TvSec  int32
	TvUsec int32
	CapLen uint32
	Len    uint32
}

type npcapFramer struct {
	handle     uintptr
	dll        *windows.DLL
	procNextEx *windows.Proc
	procSend   *windows.Proc
	procClose  *windows.Proc
	ifName     string
}

func loadPcapDLL() (*windows.DLL, error) {
	// Npcap installs to System32\Npcap\; WinPcap installs to System32\.
	candidates := []string{
		`C:\Windows\System32\Npcap\wpcap.dll`,
		`wpcap.dll`,
	}
	for _, path := range candidates {
		if dll, err := windows.LoadDLL(path); err == nil {
			return dll, nil
		}
	}
	return nil, fmt.Errorf("wpcap.dll not found (install Npcap or WinPcap)")
}

func openNpcapFramer(nicName string) (*npcapFramer, error) {
	dll, err := loadPcapDLL()
	if err != nil {
		return nil, err
	}

	var procOpen, procNext, procSend, procClose *windows.Proc
	for name, pp := range map[string]**windows.Proc{
		"pcap_open_live": &procOpen,
		"pcap_next_ex":   &procNext,
		"pcap_sendpacket": &procSend,
		"pcap_close":     &procClose,
	} {
		p, err := dll.FindProc(name)
		if err != nil {
			dll.Release()
			return nil, fmt.Errorf("npcap: %s not found: %w", name, err)
		}
		*pp = p
	}

	// Build device name: \Device\NPF_{GUID}
	guid, err := adapterGUIDByFriendlyName(nicName)
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("npcap: %w", err)
	}
	devName := `\Device\NPF_` + guid

	devBytes, _ := syscall.BytePtrFromString(devName)
	var errBuf [256]byte
	h, _, _ := procOpen.Call(
		uintptr(unsafe.Pointer(devBytes)),
		65535, // snaplen
		1,     // promisc
		100,   // to_ms (100 ms read timeout allows context cancellation checks)
		uintptr(unsafe.Pointer(&errBuf[0])),
	)
	if h == 0 {
		dll.Release()
		// Convert null-terminated C string from error buffer.
		end := 0
		for end < len(errBuf) && errBuf[end] != 0 {
			end++
		}
		return nil, fmt.Errorf("npcap: pcap_open_live %q: %s", devName, errBuf[:end])
	}

	log.Printf("bridge/npcap: opened %q (%s)", nicName, devName)
	return &npcapFramer{
		handle: h, dll: dll,
		procNextEx: procNext, procSend: procSend, procClose: procClose,
		ifName: nicName,
	}, nil
}

func (f *npcapFramer) ReadFrame(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var pktHdr uintptr
		var pktData uintptr
		r, _, _ := f.procNextEx.Call(
			f.handle,
			uintptr(unsafe.Pointer(&pktHdr)),
			uintptr(unsafe.Pointer(&pktData)),
		)

		switch int32(r) {
		case 1: // packet ready
			hdr := (*pcapPkthdr)(unsafe.Pointer(pktHdr))
			capLen := int(hdr.CapLen)
			if capLen < 14 {
				continue
			}
			frame := make([]byte, capLen)
			copy(frame, unsafe.Slice((*byte)(unsafe.Pointer(pktData)), capLen))
			return frame, nil
		case 0: // timeout, no packet — loop to check context
			runtime.Gosched()
			continue
		default:
			return nil, fmt.Errorf("npcap: pcap_next_ex error %d", int32(r))
		}
	}
}

func (f *npcapFramer) WriteFrame(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	r, _, _ := f.procSend.Call(
		f.handle,
		uintptr(unsafe.Pointer(&frame[0])),
		uintptr(len(frame)),
	)
	if int32(r) != 0 {
		return fmt.Errorf("npcap: pcap_sendpacket failed")
	}
	return nil
}

func (f *npcapFramer) Close() error {
	f.procClose.Call(f.handle)
	return f.dll.Release()
}

func (f *npcapFramer) IfName() string { return f.ifName }
