//go:build darwin

// BPF (Berkeley Packet Filter) L2 bridge for macOS.
//
// Unlike utun (which is L3), BPF binds directly to a physical NIC and captures
// full Ethernet frames — including source/destination MAC, EtherType, and payload.
// Writes to a BPF device inject frames back into the same NIC.
//
// No kernel extension or third-party driver is required.
// Access to /dev/bpf* requires root (or the 'com.apple.security.network.client'
// entitlement with a TCC/BPF exemption on newer macOS).
//
// Setup sequence:
//   open /dev/bpfN  → BIOCSETIF (bind NIC) → BIOCIMMEDIATE → BIOCPROMISC
//   → BIOCSRTIMEOUT (100 ms read timeout for ctx cancellation)
//   → BIOCSSEESENT=0 (suppress self-sent frames to prevent bridge loops)
//   → BIOCGBLEN (get read buffer size)
//
// Read returns one or more BPF-framed packets per call. Each is preceded by a
// bpf_hdr (Tstamp+Caplen+Datalen+Hdrlen); consecutive packets are aligned to
// BPF_WORDALIGN (4-byte) boundaries.  We return frames one at a time; any
// additional packets in the same read buffer are queued in darwinBPF.pending.
package tun

import (
	"context"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/atlanteg/supervpn/internal/bridge"
)

type darwinBPF struct {
	fd      int
	iface   string
	bufSize int
	pending [][]byte // frames already read but not yet returned
}

// openBPF opens a BPF device bound to ifaceName for L2 Ethernet capture/inject.
func openBPF(ifaceName string) (*darwinBPF, error) {
	fd, err := openBPFDevice()
	if err != nil {
		return nil, err
	}

	// Bind to the interface (struct ifreq: 16-byte name + 16-byte union).
	var ifreq [32]byte
	copy(ifreq[:unix.IFNAMSIZ], ifaceName)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCSETIF, uintptr(unsafe.Pointer(&ifreq[0]))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCSETIF %s: %w", ifaceName, errno)
	}

	// Return packets immediately on arrival (don't wait for buffer to fill).
	one := uint32(1)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCIMMEDIATE, uintptr(unsafe.Pointer(&one))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCIMMEDIATE: %w", errno)
	}

	// Promiscuous: capture all frames, not just those addressed to our MAC.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCPROMISC, 0); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCPROMISC: %w", errno)
	}

	// Read timeout: 100 ms so ReadFrame can wake up to check ctx.Done().
	tv := unix.Timeval32{Sec: 0, Usec: 100_000}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCSRTIMEOUT, uintptr(unsafe.Pointer(&tv))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCSRTIMEOUT: %w", errno)
	}

	// Don't see frames we inject — prevents bridge loops.
	zero := uint32(0)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCSSEESENT, uintptr(unsafe.Pointer(&zero))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCSSEESENT: %w", errno)
	}

	// Get kernel read buffer size.
	bufLen := uint32(0)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCGBLEN, uintptr(unsafe.Pointer(&bufLen))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCGBLEN: %w", errno)
	}

	return &darwinBPF{fd: fd, iface: ifaceName, bufSize: int(bufLen)}, nil
}

// openBPFDevice finds and opens the first available /dev/bpfN device.
func openBPFDevice() (int, error) {
	for i := 0; i < 256; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(path, unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		if err == unix.EBUSY {
			continue // device in use, try next
		}
		return -1, fmt.Errorf("bpf/darwin: open %s: %w", path, err)
	}
	return -1, fmt.Errorf("bpf/darwin: no available /dev/bpf device (are you root?)")
}

// bpfWordAlign rounds up to BPF_WORDALIGN (4-byte alignment).
func bpfWordAlign(n int) int { return (n + 3) &^ 3 }

// ReadFrame returns one Ethernet frame. Blocks until a frame arrives or ctx
// is cancelled. Multiple frames from one BPF read are queued internally.
func (b *darwinBPF) ReadFrame(ctx context.Context) ([]byte, error) {
	for {
		// Return queued frames before doing another read.
		if len(b.pending) > 0 {
			f := b.pending[0]
			b.pending = b.pending[1:]
			return f, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		buf := make([]byte, b.bufSize)
		n, err := unix.Read(b.fd, buf)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue // read timeout — re-check ctx
		}
		if err != nil {
			return nil, fmt.Errorf("bpf/darwin: read: %w", err)
		}

		// Parse all BPF-framed packets from the buffer.
		off := 0
		for off+int(unix.SizeofBpfHdr) <= n {
			hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
			frameStart := off + int(hdr.Hdrlen)
			frameEnd := frameStart + int(hdr.Caplen)
			if frameEnd > n {
				break
			}
			frame := make([]byte, hdr.Caplen)
			copy(frame, buf[frameStart:frameEnd])
			b.pending = append(b.pending, frame)
			off += bpfWordAlign(int(hdr.Hdrlen) + int(hdr.Caplen))
		}
	}
}

// WriteFrame injects an Ethernet frame into the bound NIC.
func (b *darwinBPF) WriteFrame(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	_, err := unix.Write(b.fd, frame)
	return err
}

func (b *darwinBPF) Close() error   { return unix.Close(b.fd) }
func (b *darwinBPF) IfName() string { return b.iface }

var _ bridge.Framer = (*darwinBPF)(nil)
