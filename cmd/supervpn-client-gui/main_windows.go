//go:build windows

package main

import "golang.org/x/sys/windows"

func init() {
	windows.FreeConsole()
}
