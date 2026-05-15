//go:build windows

package update

import (
	"log"
	"os"
	"os/exec"
)

func reexec(exe string) {
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		log.Printf("update: restart: %v — restart manually", err)
		return
	}
	os.Exit(0)
}
