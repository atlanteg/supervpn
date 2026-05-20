//go:build windows

package tun

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// ensureWintunDLL makes wintun.dll available to the Windows DLL loader before
// any wintun.CreateAdapter / wintun.OpenAdapter call.
//
// The DLL is never written next to the executable (that would clutter the user's
// program folder).  Instead it is stored in %LOCALAPPDATA%\superVPN\ — a per-user,
// persistent, out-of-the-way location.  %TEMP%\supervpn-wintun\ is used as a
// fallback when LOCALAPPDATA is unavailable (unlikely in practice).
//
// After writing, the DLL is pre-loaded by its full path.  The Windows loader
// caches loaded modules by base-name, so wintun's internal
// LoadLibraryEx("wintun.dll", SEARCH_APP_DIR|SEARCH_SYS32) reuses the cached
// handle without needing the file to be in the exe's directory.
func ensureWintunDLL() error {
	data, err := readEmbeddedWintunDLL()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		// Dev build — no DLL embedded; assume wintun.dll is already on the system.
		return nil
	}

	dllPath, err := wintunDLLPath(data)
	if err != nil {
		return err
	}

	// Pre-load by full path so the Windows loader registers "wintun.dll" in
	// the process module list — wintun's lazy loader reuses the cached handle.
	if _, err := windows.LoadLibraryEx(dllPath, 0, 0); err != nil {
		return fmt.Errorf("tun/windows: pre-load wintun.dll from %s: %w", dllPath, err)
	}
	log.Printf("tun/windows: wintun.dll ready at %s", dllPath)
	return nil
}

// wintunDLLPath returns (and if necessary creates) the path where wintun.dll
// should be stored.  Prefers %LOCALAPPDATA%\superVPN\ over the temp directory.
func wintunDLLPath(data []byte) (string, error) {
	for _, dir := range wintunCandidateDirs() {
		if err := os.MkdirAll(dir, 0755); err != nil {
			continue
		}
		dest := filepath.Join(dir, "wintun.dll")
		// Skip extraction when the file is already present.
		if _, err := os.Stat(dest); err == nil {
			return dest, nil
		}
		if err := os.WriteFile(dest, data, 0644); err != nil {
			continue
		}
		return dest, nil
	}
	return "", fmt.Errorf("tun/windows: could not extract wintun.dll to any candidate directory")
}

// wintunCandidateDirs returns directories in preference order where wintun.dll
// may be stored — all invisible from the user's program folder.
func wintunCandidateDirs() []string {
	var dirs []string
	// %LOCALAPPDATA%\superVPN — persistent, per-user, standard Windows location.
	if local, err := os.UserCacheDir(); err == nil {
		dirs = append(dirs, filepath.Join(local, "superVPN"))
	}
	// %TEMP%\supervpn-wintun — always writable fallback.
	dirs = append(dirs, filepath.Join(os.TempDir(), "supervpn-wintun"))
	return dirs
}

func readEmbeddedWintunDLL() ([]byte, error) {
	entries, err := wintunDLLFS.ReadDir("wintun-dll")
	if err != nil {
		return nil, nil // shouldn't happen, but treat as "not embedded"
	}
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(e.Name(), "wintun.dll") {
			return wintunDLLFS.ReadFile("wintun-dll/" + e.Name())
		}
	}
	return nil, nil // placeholder dir only — no real DLL embedded
}
