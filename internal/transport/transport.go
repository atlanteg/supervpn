// Package transport implements the dual-mode (UDP primary, TCP fallback) transport layer.
//
// Responsibilities:
//   - Send/receive raw frames between client and server
//   - Automatic fallback from UDP to TCP when UDP is blocked
//   - Hand raw frames to FEC encoder/decoder
//   - ТСПУ-compatibility: traffic is indistinguishable from plain TLS on port 443 (TCP mode)
package transport

import (
	"context"
	"net"
)

// Frame is a raw supervpn frame as it travels on the wire (after crypto).
type Frame struct {
	Data []byte
	Addr net.Addr // source addr (server side) or nil (client side)
}

// Sender sends frames over the wire.
type Sender interface {
	Send(f Frame) error
}

// Receiver delivers received frames.
type Receiver interface {
	Recv(ctx context.Context) (Frame, error)
}

// Transport combines Send+Recv and manages the UDP/TCP lifecycle.
type Transport interface {
	Sender
	Receiver
	// Mode returns "udp" or "tcp".
	Mode() string
	Close() error
}
