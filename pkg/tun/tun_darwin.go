//go:build darwin

// macOS TUN integration via Apple's native utun kernel control.
//
// macOS does not have a kernel TAP (L2) device; utun provides L3 (IP).
// Each packet read from or written to utun is prefixed with a 4-byte
// address-family header: [0x00, 0x00, 0x00, AF] where AF is AF_INET (2)
// or AF_INET6 (30).  We strip this header on read and prepend it on write.
//
// This matches the behaviour of WireGuard on macOS (wireguard-go/tun/tun_darwin.go).
// The supervpn server hub receives these as raw IP packets and floods them to
// all peers in the hub (MAC learning is a no-op since there are no Ethernet headers).
package tun

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/atlanteg/supervpn/internal/bridge"
	"golang.org/x/sys/unix"
)

const (
	utunControlName  = "com.apple.net.utun_control"
	utunOptIfname    = 2  // UTUN_OPT_IFNAME getsockopt option
	sysprotoControl  = 2  // SYSPROTO_CONTROL — not exported by golang.org/x/sys/unix
)

type darwinTUN struct {
	fd int
}

// openPlatform creates a new utun device.  ifaceName is ignored — macOS
// assigns the device name automatically (utun0, utun1, …).
func openPlatform(_ string) (*darwinTUN, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("tun/darwin: socket: %w", err)
	}

	// Look up the kernel control ID for "com.apple.net.utun_control".
	var ctlInfo unix.CtlInfo
	copy(ctlInfo.Name[:], utunControlName)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.CTLIOCGINFO, uintptr(unsafe.Pointer(&ctlInfo)))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun/darwin: CTLIOCGINFO: %w", errno)
	}

	// Connect creates the utun device; unit=0 lets the kernel assign the index.
	if err := unix.Connect(fd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: 0,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun/darwin: connect utun: %w", err)
	}

	return &darwinTUN{fd: fd}, nil
}

// ReadFrame reads one IP packet from the utun device.
// Blocks until a packet is available or ctx is cancelled.
// The 4-byte kernel AF prefix is stripped; callers receive a raw IP packet.
func (t *darwinTUN) ReadFrame(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Poll with a 100 ms timeout so we wake up to check ctx.Done().
		var rfds unix.FdSet
		rfds.Bits[t.fd/32] |= int32(1) << uint(t.fd%32)
		tv := unix.Timeval{Sec: 0, Usec: 100_000}
		_, err := unix.Select(t.fd+1, &rfds, nil, nil, &tv)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tun/darwin: select: %w", err)
		}
		if rfds.Bits[t.fd/32]&(int32(1)<<uint(t.fd%32)) == 0 {
			continue // timeout — re-check ctx
		}

		n, err := unix.Read(t.fd, buf)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tun/darwin: read: %w", err)
		}
		if n < 4 {
			continue // runt — skip
		}

		pkt := make([]byte, n-4)
		copy(pkt, buf[4:n])
		return pkt, nil
	}
}

// WriteFrame injects one IP packet into the utun device.
// The required 4-byte AF prefix is prepended automatically.
func (t *darwinTUN) WriteFrame(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	buf := make([]byte, 4+len(frame))
	// Bytes [0..2] are 0x00; byte [3] is the address family.
	if len(frame) > 0 && frame[0]>>4 == 6 {
		buf[3] = unix.AF_INET6
	} else {
		buf[3] = unix.AF_INET
	}
	copy(buf[4:], frame)
	_, err := unix.Write(t.fd, buf)
	return err
}

func (t *darwinTUN) Close() error { return unix.Close(t.fd) }

var _ bridge.Framer = (*darwinTUN)(nil)
