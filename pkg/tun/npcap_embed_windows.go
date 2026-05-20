//go:build windows

package tun

import "embed"

// npcap-installer/ contains the Npcap installer executable (npcap-*.exe).
// In CI the file is downloaded from https://npcap.com/ and placed here before
// the build so it is baked into the executable.  On a local dev build the
// directory is empty (.gitkeep only) and installation falls back to opening
// the download URL in the browser.
//
//go:embed all:npcap-installer
var npcapInstallerFS embed.FS
