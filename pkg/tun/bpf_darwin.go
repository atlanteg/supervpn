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
//
// Bridge loop prevention: BIOCSSEESENT=0 is unreliable on newer macOS/arm64.
// WriteFrame stores a short hash of each injected frame; ReadFrame drops any
// frame whose hash matches a recently-injected one (within 300 ms TTL).
package tun

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/atlanteg/supervpn/internal/bridge"
)

const bpfDedupTTL = 300 * time.Millisecond

type darwinBPF struct {
	fd      int
	iface   string
	bufSize int
	pending [][]byte // frames already read but not yet returned

	dedupMu   sync.Mutex
	dedupMap  map[uint64]time.Time // frame hash → time injected
	dedupDrops atomic.Uint64       // total frames dropped by dedup
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
	// Must use unix.Timeval (int64 Sec) — arm64 macOS rejects Timeval32.
	tv := unix.Timeval{Sec: 0, Usec: 100_000}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), unix.BIOCSRTIMEOUT, uintptr(unsafe.Pointer(&tv))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf/darwin: BIOCSRTIMEOUT: %w", errno)
	}

	// Don't see frames we inject — prevents bridge loops.
	// Not reliable on all macOS versions; software dedup (dedupMap) is the backstop.
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

	return &darwinBPF{
		fd:       fd,
		iface:    ifaceName,
		bufSize:  int(bufLen),
		dedupMap: make(map[uint64]time.Time),
	}, nil
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

// frameHash returns a 64-bit hash of a frame for dedup purposes.
// Short frames are zero-padded to 60 bytes (minimum Ethernet payload without
// FCS) before hashing, matching what the NIC delivers back to BPF after
// hardware padding.
func frameHash(frame []byte) uint64 {
	const minEth = 60
	if len(frame) < minEth {
		var padded [minEth]byte
		copy(padded[:], frame)
		h := sha256.Sum256(padded[:])
		return binary.LittleEndian.Uint64(h[:8])
	}
	h := sha256.Sum256(frame)
	return binary.LittleEndian.Uint64(h[:8])
}

// dedupRecord records the frame hash as recently injected.
func (b *darwinBPF) dedupRecord(frame []byte) {
	now := time.Now()
	b.dedupMu.Lock()
	b.dedupMap[frameHash(frame)] = now
	for k, t := range b.dedupMap {
		if now.Sub(t) > bpfDedupTTL {
			delete(b.dedupMap, k)
		}
	}
	b.dedupMu.Unlock()
}

// dedupSeen returns true if the frame was recently injected (bridge loop).
func (b *darwinBPF) dedupSeen(frame []byte) bool {
	b.dedupMu.Lock()
	t, ok := b.dedupMap[frameHash(frame)]
	b.dedupMu.Unlock()
	return ok && time.Since(t) < bpfDedupTTL
}

// ReadFrame returns one Ethernet frame. Blocks until a frame arrives or ctx
// is cancelled. Multiple frames from one BPF read are queued internally.
func (b *darwinBPF) ReadFrame(ctx context.Context) ([]byte, error) {
	for {
		// Return queued frames before doing another read.
		for len(b.pending) > 0 {
			f := b.pending[0]
			b.pending = b.pending[1:]
			if b.dedupSeen(f) {
				n := b.dedupDrops.Add(1)
				if n <= 10 || n%100 == 0 {
					log.Printf("bpf/darwin: dedup drop #%d src=%s dst=%s len=%d",
						n, fmtMACSlice(f[6:12]), fmtMACSlice(f[0:6]), len(f))
				}
				continue
			}
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
	b.dedupRecord(frame)
	_, err := unix.Write(b.fd, frame)
	return err
}

func (b *darwinBPF) Close() error   { return unix.Close(b.fd) }
func (b *darwinBPF) IfName() string { return b.iface }

func fmtMACSlice(b []byte) string {
	if len(b) < 6 {
		return "?"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

var _ bridge.Framer = (*darwinBPF)(nil)
