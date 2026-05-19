//go:build windows

// tap-windows6 integration for bridge mode.
//
// tap-windows6 is the OpenVPN TAP driver — it creates a virtual Ethernet adapter
// (L2, full Ethernet frames with MAC headers) unlike WinTun which is L3 (raw IP).
//
// In bridge mode the TAP adapter is added to a Windows Network Bridge together
// with the physical 169.254.x.x NIC.  Windows handles the L2 forwarding; supervpn
// reads and writes Ethernet frames via the TAP device endpoint.
//
// Device access: the driver exposes a char device at \\.\Global\{GUID}.tap.
// We use overlapped (async) I/O so ReadFrame can respect context cancellation.
//
// IOCTL TAP_WIN_IOCTL_SET_MEDIA_STATUS (0x00220018) brings the virtual link up;
// without it the adapter stays in a disconnected state.
package tun

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/atlanteg/supervpn/internal/bridge"
)

// TAP_WIN_IOCTL_SET_MEDIA_STATUS:
// CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, func=6, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
const tapIOCtlSetMediaStatus = (0x22 << 16) | (6 << 2) // 0x00220018

// Network adapter class GUID — used to scan for TAP adapters in the registry.
const netAdapterClass = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`

type windowsTAP struct {
	handle windows.Handle
	name   string
}

// OpenTAP opens a tap-windows6 adapter by its friendly name and returns a Framer
// that reads and writes raw Ethernet frames (L2 — with MAC headers).
//
// If no adapter with the requested name exists but another tap0901 adapter is
// installed, OpenTAP renames it automatically (requires Administrator).
func OpenTAP(name string) (bridge.Framer, error) {
	guid, err := tapGUIDByName(name)
	if err != nil {
		// No adapter with the expected name — find any tap0901 and rename it.
		guid2, oldName, findErr := findAnyTAP0901()
		if findErr != nil {
			// No tap0901 adapter at all — try auto-install via devcon.exe.
			log.Printf("tap/windows: no tap0901 adapter found, attempting auto-install via devcon.exe ...")
			if installErr := installTAPDriver(); installErr != nil {
				return nil, fmt.Errorf("tap/windows: adapter %q not found and auto-install failed: %v (place tap-driver/ next to supervpn-client.exe)", name, installErr)
			}
			time.Sleep(3 * time.Second) // wait for Windows to register the new device
			guid2, oldName, findErr = findAnyTAP0901()
			if findErr != nil {
				return nil, fmt.Errorf("tap/windows: adapter not found after install — reboot and retry: %w", findErr)
			}
		}
		log.Printf("tap/windows: renaming TAP adapter %q → %q", oldName, name)
		if renErr := renameTAPAdapter(oldName, name); renErr != nil {
			return nil, fmt.Errorf("tap/windows: found TAP adapter %q but rename failed: %w", oldName, renErr)
		}
		guid = guid2
	}

	devPath, _ := windows.UTF16PtrFromString(`\\.\Global\` + guid + `.tap`)
	h, err := windows.CreateFile(devPath,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_SYSTEM|windows.FILE_FLAG_OVERLAPPED,
		0)
	if err != nil {
		return nil, fmt.Errorf("tap/windows: open %s: %w", guid, err)
	}

	// Bring virtual link up (media connected).
	up := [4]byte{1, 0, 0, 0}
	var ret uint32
	if err := windows.DeviceIoControl(h, tapIOCtlSetMediaStatus,
		&up[0], 4, &up[0], 4, &ret, nil); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("tap/windows: set media status: %w", err)
	}

	tap := &windowsTAP{handle: h, name: name}
	configureTAPDirectIP(name, guid)
	return tap, nil
}

// tapLinkLocalIP derives a stable 169.254.x.y address from an adapter GUID.
// Uses bytes 4-5 of the first GUID group so the address survives reboots.
func tapLinkLocalIP(guid string) string {
	g := strings.Trim(guid, "{}")
	parts := strings.Split(g, "-")
	if len(parts) == 0 || len(parts[0]) < 8 {
		return "169.254.1.1"
	}
	b2, e2 := strconv.ParseUint(parts[0][4:6], 16, 8)
	b3, e3 := strconv.ParseUint(parts[0][6:8], 16, 8)
	if e2 != nil || e3 != nil {
		return "169.254.1.1"
	}
	if b2 == 0 && b3 == 0 {
		b2, b3 = 1, 1
	}
	if b2 == 255 && b3 == 255 {
		b2, b3 = 254, 254
	}
	return fmt.Sprintf("169.254.%d.%d", b2, b3)
}

// configureTAPDirectIP assigns a 169.254.x.y address to the TAP adapter so that
// BMW ENET / ZGW Search discovery tools find it via GetAdaptersAddresses.
// Non-fatal: a warning is logged on failure so the VPN still connects.
func configureTAPDirectIP(name, guid string) {
	ip := tapLinkLocalIP(guid)
	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+name, "static", ip, "255.255.0.0").CombinedOutput()
	if err != nil {
		log.Printf("tap/windows: %s: link-local IP warning: %v: %s", name, err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("tap/windows: %s: assigned %s/16 (link-local, BMW ENET discovery)", name, ip)
}

// tapGUIDByName scans the registry network-adapter class for tap0901 entries and
// returns the NetCfgInstanceId GUID for the adapter with the matching friendly name.
func tapGUIDByName(name string) (string, error) {
	cls, err := registry.OpenKey(registry.LOCAL_MACHINE, netAdapterClass, registry.READ)
	if err != nil {
		return "", fmt.Errorf("open adapter class key: %w", err)
	}
	defer cls.Close()

	subkeys, err := cls.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}

	for _, sk := range subkeys {
		sub, err := registry.OpenKey(cls, sk, registry.READ)
		if err != nil {
			continue
		}
		compID, _, _ := sub.GetStringValue("ComponentId")
		sub.Close()
		if !strings.EqualFold(compID, "tap0901") {
			continue
		}

		sub2, err := registry.OpenKey(cls, sk, registry.READ)
		if err != nil {
			continue
		}
		guid, _, err := sub2.GetStringValue("NetCfgInstanceId")
		sub2.Close()
		if err != nil || guid == "" {
			continue
		}

		friendly, err := tapAdapterName(guid)
		if err != nil {
			continue
		}
		if strings.EqualFold(friendly, name) {
			return guid, nil
		}
	}
	return "", fmt.Errorf("no tap0901 adapter named %q (check Device Manager)", name)
}

// tapAdapterName returns the friendly name for a network adapter GUID from
// HKLM\SYSTEM\CurrentControlSet\Control\Network\{class}\{guid}\Connection\Name.
func tapAdapterName(guid string) (string, error) {
	path := `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\` + guid + `\Connection`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return "", err
	}
	defer k.Close()
	name, _, err := k.GetStringValue("Name")
	return name, err
}

// findAnyTAP0901 returns the GUID and friendly name of the first tap0901
// adapter found in the registry, regardless of its current name.
func findAnyTAP0901() (guid, name string, err error) {
	cls, err := registry.OpenKey(registry.LOCAL_MACHINE, netAdapterClass, registry.READ)
	if err != nil {
		return "", "", fmt.Errorf("open adapter class key: %w", err)
	}
	defer cls.Close()

	subkeys, err := cls.ReadSubKeyNames(-1)
	if err != nil {
		return "", "", err
	}
	for _, sk := range subkeys {
		sub, err := registry.OpenKey(cls, sk, registry.READ)
		if err != nil {
			continue
		}
		compID, _, _ := sub.GetStringValue("ComponentId")
		g, _, _ := sub.GetStringValue("NetCfgInstanceId")
		sub.Close()
		if !strings.EqualFold(compID, "tap0901") || g == "" {
			continue
		}
		friendly, err := tapAdapterName(g)
		if err != nil {
			continue
		}
		return g, friendly, nil
	}
	return "", "", fmt.Errorf("no tap0901 adapter installed")
}

// installTAPDriver installs the tap0901 driver using pnputil.exe (built into
// Windows Vista+). Driver files are embedded in the binary by tapdrv_embed_windows.go;
// if the embedded package is empty (local dev build), falls back to a tap-driver/
// subdirectory next to the running executable.
// Requires Administrator privileges.
func installTAPDriver() error {
	// Check whether CI embedded real driver files (indicated by a .sys file).
	entries, _ := tapDriverFS.ReadDir("tap-driver")
	for _, e := range entries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".sys") {
			return installTAPDriverFromEmbed()
		}
	}
	// Fall back: look for driver files on disk next to the executable.
	return installTAPDriverFromDisk()
}

// installTAPDriverFromEmbed extracts the embedded driver package to a temp
// directory and installs it with pnputil.
func installTAPDriverFromEmbed() error {
	tmp, err := os.MkdirTemp("", "tapdrv-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	entries, _ := tapDriverFS.ReadDir("tap-driver")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := tapDriverFS.ReadFile("tap-driver/" + e.Name())
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(tmp, e.Name()), data, 0o644); err != nil {
			return fmt.Errorf("write %s to temp: %w", e.Name(), err)
		}
	}

	inf := filepath.Join(tmp, "OemVista.inf")
	if _, err := os.Stat(inf); err != nil {
		return fmt.Errorf("OemVista.inf not found in embedded driver package")
	}
	return runPnpUtil(inf)
}

// installTAPDriverFromDisk looks for OemVista.inf in a tap-driver/ subdirectory
// next to the running executable and installs it with pnputil.
func installTAPDriverFromDisk() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	inf := filepath.Join(filepath.Dir(exe), "tap-driver", "OemVista.inf")
	if _, err := os.Stat(inf); err != nil {
		return fmt.Errorf("TAP driver not embedded and OemVista.inf not found at %s — place tap-windows6 driver files in tap-driver/ next to the executable", inf)
	}
	return runPnpUtil(inf)
}

// runPnpUtil stages and installs an INF driver package using the built-in
// pnputil.exe (available since Windows Vista, no additional tools required).
func runPnpUtil(inf string) error {
	out, err := exec.Command("pnputil.exe", "/add-driver", inf, "/install").CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("pnputil /add-driver: %v: %s", err, msg)
	}
	log.Printf("tap/windows: driver installed via pnputil: %s", msg)
	return nil
}

// renameTAPAdapter renames a network adapter using PowerShell Rename-NetAdapter.
func renameTAPAdapter(oldName, newName string) error {
	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Rename-NetAdapter -Name %s -NewName %s",
			tapPSQuote(oldName), tapPSQuote(newName)),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Rename-NetAdapter: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// tapPSQuote wraps s in PowerShell single quotes so wildcards are not expanded.
func tapPSQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (t *windowsTAP) ReadFrame(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 65536)
	ol := new(windows.Overlapped)
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("tap/windows: create event: %w", err)
	}
	ol.HEvent = ev
	defer windows.CloseHandle(ev)

	var n uint32
	err = windows.ReadFile(t.handle, buf, &n, ol)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return nil, fmt.Errorf("tap/windows: read: %w", err)
	}

	for {
		r, _ := windows.WaitForSingleObject(ev, 100) // 100 ms poll
		if r == windows.WAIT_OBJECT_0 {
			break
		}
		select {
		case <-ctx.Done():
			windows.CancelIoEx(t.handle, ol)
			return nil, ctx.Err()
		default:
		}
	}

	if err := windows.GetOverlappedResult(t.handle, ol, &n, false); err != nil {
		return nil, fmt.Errorf("tap/windows: read result: %w", err)
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

func (t *windowsTAP) WriteFrame(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	ol := new(windows.Overlapped)
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("tap/windows: create event: %w", err)
	}
	ol.HEvent = ev
	defer windows.CloseHandle(ev)

	var n uint32
	err = windows.WriteFile(t.handle, frame, &n, ol)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return fmt.Errorf("tap/windows: write: %w", err)
	}
	windows.WaitForSingleObject(ev, windows.INFINITE)
	if err := windows.GetOverlappedResult(t.handle, ol, &n, false); err != nil {
		return fmt.Errorf("tap/windows: write result: %w", err)
	}
	return nil
}

func (t *windowsTAP) Close() error  { return windows.CloseHandle(t.handle) }
func (t *windowsTAP) IfName() string { return t.name }

var _ bridge.Framer = (*windowsTAP)(nil)
