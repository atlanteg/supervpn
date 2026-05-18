//go:build windows

package tun

import "embed"

// tapDriverFS embeds the tap-windows6 driver package (OemVista.inf, tap0901.sys,
// tap0901.cat) that CI downloads before building.
//
// In a local dev checkout only tap-driver/.gitkeep is present; installTAPDriver
// detects the missing .sys file and falls back to looking for the driver files
// next to the running executable.
//
// "all:" includes hidden files such as .gitkeep so the build succeeds even
// when CI has not yet downloaded the real driver files.
//go:embed all:tap-driver
var tapDriverFS embed.FS
