//go:build !windows

package update

import (
	"log"
	"os"
	"syscall"
)

func reexec(exe string) {
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Printf("update: exec: %v — restart manually", err)
	}
}
