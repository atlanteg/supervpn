package vpnclient

import (
	"context"
	"fmt"
	"time"

	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
)

// FetchHubs connects to the VPN server and requests the hub list without
// authenticating.  The server responds to FrameListHubs immediately; the
// call returns after receiving the first valid response or when the context
// is cancelled.
//
// addr must be in "host:port" format (the main VPN UDP port).
// A 4-second deadline is applied automatically when the context has none.
func FetchHubs(ctx context.Context, addr string) ([]proto.HubInfo, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
	}

	tr, err := transport.DialUDP(addr)
	if err != nil {
		return nil, fmt.Errorf("fetch hubs: dial %s: %w", addr, err)
	}
	defer tr.Close()

	// Send FrameListHubs request — no payload, hub_id/session_id/seq all zero.
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameListHubs}.Marshal(hdr)
	if err := tr.Send(transport.Frame{Data: hdr}); err != nil {
		return nil, fmt.Errorf("fetch hubs: send: %w", err)
	}

	for {
		f, err := tr.Recv(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetch hubs: recv: %w", err)
		}
		h, ok := proto.ParseHeader(f.Data)
		if !ok || h.Type != proto.FrameListHubs {
			continue
		}
		return proto.ParseHubList(f.Data[proto.HeaderSize:])
	}
}
