//go:build windows && !fyne

package main

import (
	"strings"
	"syscall"
	"unsafe"

	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

var (
	_user32          = windows.NewLazySystemDLL("user32.dll")
	_getWindowTextW  = _user32.NewProc("GetWindowTextW")
)

func getWindowText(hwnd win.HWND) string {
	var buf [512]uint16
	_getWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf[:])
}

// Session-local namespace (not Global\): on a terminal server each RDP session
// gets its own instance instead of one session's mutex blocking every other
// session (which left the window failing to appear on Windows Server 2008 R2).
const _singleInstanceMutexName = "Local\\superVPN-supervpn-client-gui"

var _singleInstanceMutexHandle windows.Handle

// acquireSingleInstance creates a named global mutex. Returns true when this
// is the first running instance. If another instance is already running its
// main window is brought to the foreground and false is returned — caller
// should exit immediately.
func acquireSingleInstance() bool {
	name, err := windows.UTF16PtrFromString(_singleInstanceMutexName)
	if err != nil {
		return true
	}
	h, err := windows.CreateMutex(nil, false, name)
	switch err {
	case nil:
		_singleInstanceMutexHandle = h
		return true
	case windows.ERROR_ALREADY_EXISTS:
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		bringExistingInstanceToFront()
		return false
	default:
		// Access denied or unexpected error — let the process proceed.
		return true
	}
}

// bringExistingInstanceToFront enumerates all top-level windows and restores
// the first one whose title starts with "superVPN".
func bringExistingInstanceToFront() {
	cb := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		if strings.HasPrefix(getWindowText(win.HWND(hwnd)), "superVPN") {
			win.ShowWindow(win.HWND(hwnd), win.SW_RESTORE)
			win.SetForegroundWindow(win.HWND(hwnd))
			return 0 // stop enumeration
		}
		return 1 // continue
	})
	_ = windows.EnumWindows(cb, nil)
}
