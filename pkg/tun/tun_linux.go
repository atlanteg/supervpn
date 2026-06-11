//go:build linux

package tun

import (
	"context"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type linuxTAP struct {
	f *os.File
}

func openPlatform(name string) (*linuxTAP, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	// IFF_TAP | IFF_NO_PI
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TAP | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}
	// A freshly created TAP is administratively DOWN; writing frames to a DOWN
	// interface fails with EIO. Bring it UP so downstream writes succeed.
	if err := setIfaceUp(name); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: bring %q up: %w", name, err)
	}
	return &linuxTAP{f: os.NewFile(uintptr(fd), name)}, nil
}

func setIfaceUp(name string) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	flags := (*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))
	*flags |= unix.IFF_UP | unix.IFF_RUNNING
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	return nil
}

func (t *linuxTAP) ReadFrame(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 2048)
	n, err := t.f.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *linuxTAP) WriteFrame(frame []byte) error {
	_, err := t.f.Write(frame)
	return err
}

func (t *linuxTAP) Close() error { return t.f.Close() }
