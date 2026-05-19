//go:build windows

package tun

import "embed"

// wintun-dll/ contains wintun.dll for amd64.
// In CI the file is downloaded from https://wintun.net/ and placed here before
// the build so it is baked into the executable.  On a local dev build the
// directory is empty (.gitkeep only) and the DLL must be present on the system.
//
//go:embed all:wintun-dll
var wintunDLLFS embed.FS
