//go:build windows

package tun

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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

	// injMu protects injectedSrc. When WriteFrame injects a frame, the frame's
	// source MAC is added here BEFORE pcap_sendpacket so that ReadFrame can skip
	// any looped-back copy. Windows NDIS may reflect injected frames (especially
	// broadcast ARP) back to the receive path; without this filter the hub's MAC
	// table would map remote VPN client MACs to the bridge session, causing
	// replies destined for those clients to be sent to the wrong endpoint.
	injMu       sync.Mutex
	injectedSrc map[[6]byte]struct{}
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
		"pcap_open_live":  &procOpen,
		"pcap_next_ex":    &procNext,
		"pcap_sendpacket": &procSend,
		"pcap_close":      &procClose,
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
		ifName:      nicName,
		injectedSrc: make(map[[6]byte]struct{}),
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
			// Skip frames whose source MAC we injected — NDIS may loop back
			// injected broadcasts to the receive path (see injectedSrc comment).
			var srcMAC [6]byte
			pkt := unsafe.Slice((*byte)(unsafe.Pointer(pktData)), capLen)
			copy(srcMAC[:], pkt[6:12])
			f.injMu.Lock()
			_, looped := f.injectedSrc[srcMAC]
			f.injMu.Unlock()
			if looped {
				continue
			}
			frame := make([]byte, capLen)
			copy(frame, pkt)
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
	// Record the injected source MAC BEFORE sending so ReadFrame can suppress
	// any NDIS loopback copy of this frame.
	if len(frame) >= 14 {
		var src [6]byte
		copy(src[:], frame[6:12])
		f.injMu.Lock()
		f.injectedSrc[src] = struct{}{}
		f.injMu.Unlock()
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

// ── Npcap install helpers ─────────────────────────────────────────────────────

// NpcapInstalled reports whether Npcap (or legacy WinPcap) is installed.
// Three independent checks are used so that any installation layout is caught:
//
//  1. Registry SOFTWARE\Npcap or SOFTWARE\WinPcap (standard installer key).
//  2. Service entry in SYSTEM\CurrentControlSet\Services (npcap or npf).
//  3. wpcap.dll on disk — Npcap puts it in System32\Npcap\, WinPcap in System32\.
func NpcapInstalled() bool {
	// 1. Installer registry key.
	for _, p := range []string{`SOFTWARE\Npcap`, `SOFTWARE\WinPcap`} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ); err == nil {
			k.Close()
			return true
		}
	}
	// 2. Windows service key (present even without the SOFTWARE key on some installs).
	for _, p := range []string{
		`SYSTEM\CurrentControlSet\Services\npcap`,
		`SYSTEM\CurrentControlSet\Services\npf`,
	} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ); err == nil {
			k.Close()
			return true
		}
	}
	// 3. DLL on disk (most reliable — the DLL must exist for capture to work).
	for _, dll := range []string{
		`C:\Windows\System32\Npcap\wpcap.dll`,
		`C:\Windows\System32\wpcap.dll`,
	} {
		if _, err := os.Stat(dll); err == nil {
			return true
		}
	}
	return false
}

// windows7OrOlder reports whether the host is Windows 7 / Vista or older
// (NT 6.1 or below). Such hosts reject Npcap drivers newer than 1.79 after the
// June-2024 cross-cert expiry, so WinPcap is the reliable capture provider.
func windows7OrOlder() bool {
	v := windows.RtlGetVersion()
	if v.MajorVersion < 6 {
		return true
	}
	return v.MajorVersion == 6 && v.MinorVersion <= 1
}

// InstallNpcap runs an embedded packet-capture installer. When both Npcap and
// WinPcap installers are embedded (the 32-bit Win7 build), WinPcap is chosen on
// Windows 7/Vista and Npcap on newer Windows. If no installer is embedded
// (local dev build), opens the download page in the browser and returns an
// error so the caller knows to wait for a manual install.
func InstallNpcap() error {
	entries, _ := npcapInstallerFS.ReadDir("npcap-installer")
	var npcapExe, winpcapExe string
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if !strings.HasSuffix(n, ".exe") {
			continue
		}
		if strings.Contains(n, "winpcap") {
			winpcapExe = e.Name()
		} else {
			npcapExe = e.Name()
		}
	}

	if winpcapExe != "" && (npcapExe == "" || windows7OrOlder()) {
		log.Printf("npcap: installing WinPcap (Win7-compatible capture driver)")
		return runEmbeddedNpcapInstaller(winpcapExe)
	}
	if npcapExe != "" {
		return runEmbeddedNpcapInstaller(npcapExe)
	}

	log.Printf("npcap: no embedded installer — opening download page")
	exec.Command("rundll32", "url.dll,FileProtocolHandler",
		"https://npcap.com/dist/npcap-1.88.exe").Start()
	return fmt.Errorf("npcap installer not embedded; download started in browser")
}

func runEmbeddedNpcapInstaller(name string) error {
	data, err := npcapInstallerFS.ReadFile("npcap-installer/" + name)
	if err != nil {
		return fmt.Errorf("npcap: read embedded installer: %w", err)
	}
	tmp, err := os.MkdirTemp("", "npcap-*")
	if err != nil {
		return fmt.Errorf("npcap: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	dst := filepath.Join(tmp, name)
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return fmt.Errorf("npcap: write installer: %w", err)
	}
	// Run the installer normally (no /S flag — silent install is OEM-only).
	// The user will see the standard Npcap setup wizard.
	out, err := exec.Command(dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("npcap installer: %v: %s", err, out)
	}
	log.Printf("npcap: installed from embedded installer")
	return nil
}
