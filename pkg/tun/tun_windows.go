//go:build windows

// WinTun integration — uses the official WireGuard WinTun driver.
// Driver DLL must be present: wintun.dll (ship with installer).
// See: https://wintun.net/
package tun

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

type windowsTUN struct {
	adapter *wintun.Adapter
	session wintun.Session
}

func openPlatform(name string) (*windowsTUN, error) {
	adapter, err := wintun.CreateAdapter(name, "supervpn", nil)
	if err != nil {
		// try to open existing
		adapter, err = wintun.OpenAdapter(name)
		if err != nil {
			return nil, fmt.Errorf("tun/windows: open adapter %q: %w", name, err)
		}
	}
	session, err := adapter.StartSession(0x800000) // 8 MiB ring
	if err != nil {
		return nil, fmt.Errorf("tun/windows: start session: %w", err)
	}
	return &windowsTUN{adapter: adapter, session: session}, nil
}

func (t *windowsTUN) ReadFrame(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		pkt, err := t.session.ReceivePacket()
		if err != nil {
			// no packet yet — wait for driver signal via Win32 event handle
			evt := t.session.ReadWaitEvent()
			_, _ = windows.WaitForSingleObject(evt, 100)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("tun/windows: recv: %w", err)
		}
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		t.session.ReleaseReceivePacket(pkt)
		return cp, nil
	}
}

func (t *windowsTUN) WriteFrame(frame []byte) error {
	pkt, err := t.session.AllocateSendPacket(len(frame))
	if err != nil {
		return fmt.Errorf("tun/windows: alloc send: %w", err)
	}
	copy(pkt, frame)
	t.session.SendPacket(pkt)
	return nil
}

func (t *windowsTUN) Close() error {
	t.session.End()
	return t.adapter.Close()
}
