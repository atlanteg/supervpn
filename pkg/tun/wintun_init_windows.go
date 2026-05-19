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
// Strategy (two-stage):
//  1. Try to write the DLL next to the running executable — wintun's internal
//     LoadLibraryEx uses LOAD_LIBRARY_SEARCH_APPLICATION_DIR, so it will find
//     the file there automatically.
//  2. If the exe directory is not writable (e.g. Program Files), extract to
//     %TEMP%\supervpn-wintun\ and pre-load the DLL by its full path.
//     The Windows loader caches loaded modules by base-name; a subsequent
//     LoadLibraryEx("wintun.dll", SEARCH_APP_DIR|SEARCH_SYS32) from the
//     wintun package finds the already-loaded module and returns its handle.
func ensureWintunDLL() error {
	data, err := readEmbeddedWintunDLL()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		// Dev build — no DLL embedded; assume wintun.dll is already on the system.
		return nil
	}

	// Stage 1: next to the executable (preferred — found by SEARCH_APPLICATION_DIR).
	if exe, err := os.Executable(); err == nil {
		dest := filepath.Join(filepath.Dir(exe), "wintun.dll")
		if _, err := os.Stat(dest); err == nil {
			return nil // already present
		}
		if err := os.WriteFile(dest, data, 0644); err == nil {
			log.Printf("tun/windows: wintun.dll extracted to %s", dest)
			return nil
		}
	}

	// Stage 2: temp directory + pre-load by full path.
	tmpDir := filepath.Join(os.TempDir(), "supervpn-wintun")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("tun/windows: mkdir for wintun.dll: %w", err)
	}
	tmpDLL := filepath.Join(tmpDir, "wintun.dll")
	if _, err := os.Stat(tmpDLL); err != nil {
		if err := os.WriteFile(tmpDLL, data, 0644); err != nil {
			return fmt.Errorf("tun/windows: extract wintun.dll to temp: %w", err)
		}
	}
	// Pre-load by full path so the Windows loader registers "wintun.dll" in
	// the process module list — wintun's lazy loader reuses the cached handle.
	if _, err := windows.LoadLibraryEx(tmpDLL, 0, 0); err != nil {
		return fmt.Errorf("tun/windows: pre-load wintun.dll from %s: %w", tmpDLL, err)
	}
	log.Printf("tun/windows: wintun.dll pre-loaded from %s", tmpDLL)
	return nil
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
