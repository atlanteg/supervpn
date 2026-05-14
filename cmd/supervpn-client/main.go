// supervpn-client — L2 VPN client with transparent 169.254.0.0/16 bridge.
// Detects local interfaces with link-local addresses and bridges them to
// the supervpn server hub via UDP (with TCP fallback).
//
// Usage:
//
//	supervpn-client -server host:5555 -hub 1 -login user -password pass
//	supervpn-client -config /etc/supervpn/client.toml
package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/crypto"
	"github.com/atlanteg/supervpn/internal/fec"
	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
	"github.com/atlanteg/supervpn/pkg/tun"
)

var version = "dev"

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to client config file (optional)")

	// Inline flags for convenience — overridden by config file when both provided.
	var (
		serverFlag   = flag.String("server", "", "server UDP address host:port")
		hubIDFlag    = flag.Uint("hub", 1, "hub ID")
		loginFlag    = flag.String("login", "", "login")
		passwordFlag = flag.String("password", "", "password")
	)
	flag.Parse()

	var cfg config.ClientConfig
	if cfgPath != "" {
		loaded, err := config.LoadClientConfig(cfgPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		cfg = *loaded
	} else {
		cfg.Server = *serverFlag
		cfg.HubID = uint16(*hubIDFlag)
		cfg.Login = *loginFlag
		cfg.Password = *passwordFlag
		cfg.FEC = config.FECConfig{K: 20, R: 1}
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Detect 169.254.0.0/16 interfaces.
	ifaces, err := bridge.DetectLinkLocal()
	if err != nil {
		log.Fatalf("bridge: detect interfaces: %v", err)
	}
	if len(ifaces) == 0 {
		log.Fatalf("bridge: no 169.254.0.0/16 interfaces found — nothing to bridge")
	}
	for _, iface := range ifaces {
		log.Printf("bridge: detected link-local interface %s (%s)", iface.Name, iface.HWAddr)
	}
	iface := ifaces[0] // use first detected interface

	// Open TUN/TAP adapter.
	framer, err := tun.Open(iface.Name)
	if err != nil {
		log.Fatalf("tun: open %s: %v", iface.Name, err)
	}
	defer framer.Close()
	log.Printf("tun: opened adapter for %s", iface.Name)

	log.Printf("supervpn-client %s: connecting to %s hub=%d login=%s",
		version, cfg.Server, cfg.HubID, cfg.Login)

	// Reconnect loop with exponential backoff.
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := runSession(ctx, cfg, iface, framer)
		if ctx.Err() != nil {
			return
		}
		log.Printf("session ended: %v — reconnecting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// runSession dials the server, authenticates, runs the bridge, and returns on error.
func runSession(ctx context.Context, cfg config.ClientConfig, iface bridge.Interface, framer bridge.Framer) error {
	// Connect UDP.
	tr, err := transport.DialUDP(cfg.Server)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer tr.Close()

	// Authenticate and obtain session cipher.
	sessionID, sessionCipher, err := authenticate(ctx, tr, cfg)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	log.Printf("authenticated: session=%d", sessionID)

	fecCfg := cfg.FEC.WithDefaults()

	// FEC pipe: sendFECData/sendFECRepair callbacks use the same cipher+transport.
	pipe, err := fec.NewPipe(
		fecCfg.K,
		fecCfg.R,
		func(blockID uint32, pktIdx uint16, data []byte) error {
			return sendFECData(tr, sessionID, cfg.HubID, sessionCipher, blockID, pktIdx, data)
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			return sendFECRepair(tr, sessionID, cfg.HubID, sessionCipher, blockID, repairIdx, uint8(fecCfg.K), uint8(fecCfg.R), data)
		},
	)
	if err != nil {
		return fmt.Errorf("fec pipe: %w", err)
	}

	// Set up bridge.
	downstream := make(chan []byte, 64)
	b := bridge.New(iface, framer, func(frame []byte) error {
		return pipe.Send(frame)
	})

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	// Upstream: local interface → server.
	upErr := make(chan error, 1)
	go func() { upErr <- b.RunUpstream(sessionCtx) }()

	// Downstream: server frames → local interface.
	downErr := make(chan error, 1)
	go func() { downErr <- b.RunDownstream(sessionCtx, downstream) }()

	// Receive loop: UDP → downstream channel.
	recvErr := make(chan error, 1)
	go func() {
		recvErr <- recvLoop(sessionCtx, tr, sessionID, sessionCipher, pipe, downstream)
	}()

	// Keepalive ping every 25 seconds.
	pingTick := time.NewTicker(25 * time.Second)
	defer pingTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-upErr:
			return fmt.Errorf("upstream: %w", err)
		case err := <-downErr:
			return fmt.Errorf("downstream: %w", err)
		case err := <-recvErr:
			return fmt.Errorf("recv: %w", err)
		case <-pingTick.C:
			sendPing(tr, sessionID, cfg.HubID)
		}
	}
}

// authenticate sends AuthHello and waits for AuthOK or AuthError.
// Returns the session ID and a Cipher keyed from the shared secret.
func authenticate(ctx context.Context, tr *transport.UDPTransport, cfg config.ClientConfig) (uint32, *crypto.Cipher, error) {
	// Compute raw SHA-256 of password for wire transmission (AuthHello.PWHash).
	pwHash := sha256.Sum256([]byte(cfg.Password))

	hello := proto.AuthHello{
		HubID:  cfg.HubID,
		Login:  cfg.Login,
		PWHash: pwHash,
	}
	payload := append([]byte{proto.AuthMsgHello}, hello.Marshal()...)
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameAuth, HubID: cfg.HubID}.Marshal(hdr)
	if err := tr.Send(transport.Frame{Data: append(hdr, payload...)}); err != nil {
		return 0, nil, fmt.Errorf("send AuthHello: %w", err)
	}

	// Wait for server response with a 10-second timeout.
	authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for {
		f, err := tr.Recv(authCtx)
		if err != nil {
			return 0, nil, fmt.Errorf("waiting for auth response: %w", err)
		}
		respHdr, ok := proto.ParseHeader(f.Data)
		if !ok || respHdr.Type != proto.FrameAuth {
			continue
		}
		resp := f.Data[proto.HeaderSize:]
		if len(resp) == 0 {
			continue
		}
		switch resp[0] {
		case proto.AuthMsgOK:
			authOK, err := proto.ParseAuthOK(resp[1:])
			if err != nil {
				return 0, nil, fmt.Errorf("parse AuthOK: %w", err)
			}
			// Derive session cipher using the wire-hex of the password as token.
			// The hub name is formatted as "hub<ID>" to match the server-side hub.Name().
			// Note: the server uses storedHash (bcrypt) as token; this client uses wireHex.
			// Both sides must agree on the token — a coordinated server change may be needed.
			wireHex := wireHashHex(cfg.Password)
			hubName := fmt.Sprintf("hub%d", cfg.HubID)
			key, err := crypto.DeriveKey(wireHex, hubName, cfg.Login, "server")
			if err != nil {
				return 0, nil, fmt.Errorf("derive key: %w", err)
			}
			sessionCipher, err := crypto.NewCipher(key, authOK.SessionID)
			if err != nil {
				return 0, nil, fmt.Errorf("new cipher: %w", err)
			}
			return authOK.SessionID, sessionCipher, nil

		case proto.AuthMsgError:
			ae, _ := proto.ParseAuthError(resp[1:])
			return 0, nil, fmt.Errorf("server rejected auth: %s", ae.Message)
		}
	}
}

// wireHashHex returns the hex-encoded SHA-256 of the password — the same value
// the server receives as wireHex when it does hex.EncodeToString(hello.PWHash[:]).
func wireHashHex(password string) string {
	sum := sha256.Sum256([]byte(password))
	const hextable = "0123456789abcdef"
	buf := make([]byte, 64)
	for i, b := range sum {
		buf[i*2] = hextable[b>>4]
		buf[i*2+1] = hextable[b&0xf]
	}
	return string(buf)
}

// recvLoop reads UDP frames from the server, decrypts data and repair frames,
// feeds them to the FEC pipe decoder, and forwards recovered frames to the
// downstream channel. Returns on context cancellation or transport error.
func recvLoop(ctx context.Context, tr *transport.UDPTransport, sessionID uint32, cipher *crypto.Cipher, pipe *fec.Pipe, out chan<- []byte) error {
	var replay crypto.ReplayWindow
	for {
		f, err := tr.Recv(ctx)
		if err != nil {
			return err
		}
		hdr, ok := proto.ParseHeader(f.Data)
		if !ok {
			continue
		}
		if hdr.SessionID != sessionID && hdr.Type != proto.FrameAuth {
			continue
		}
		payload := f.Data[proto.HeaderSize:]

		switch hdr.Type {
		case proto.FrameData:
			frame, err := cipher.Open(payload, &replay)
			if err != nil {
				continue
			}
			blockID, pktIdx := proto.UnpackDataSeq(hdr.Seq)
			recovered, err := pipe.RecvData(blockID, pktIdx, frame)
			if err != nil || recovered == nil {
				continue
			}
			for _, rf := range recovered {
				if len(rf) < 14 {
					continue
				}
				select {
				case out <- rf:
				case <-ctx.Done():
					return ctx.Err()
				}
			}

		case proto.FrameRepair:
			frame, err := cipher.Open(payload, &replay)
			if err != nil {
				continue
			}
			blockID, repairIdx, blockK, blockR := proto.UnpackRepairSeq(hdr.Seq)
			recovered, err := pipe.RecvRepair(blockID, repairIdx, blockK, blockR, frame)
			if err != nil || recovered == nil {
				continue
			}
			for _, rf := range recovered {
				if len(rf) < 14 {
					continue
				}
				select {
				case out <- rf:
				case <-ctx.Done():
					return ctx.Err()
				}
			}

		case proto.FramePong:
			// Keepalive acknowledged — nothing to do.
		}
	}
}

// sendFECData encrypts one data frame and sends it as a FrameData packet to the server.
// Called by the FEC pipe's sendData callback.
func sendFECData(tr *transport.UDPTransport, sessionID uint32, hubID uint16, cipher *crypto.Cipher, blockID uint32, pktIdx uint16, frame []byte) error {
	encrypted, err := cipher.Seal(frame)
	if err != nil {
		return err
	}
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{
		Type:      proto.FrameData,
		HubID:     hubID,
		SessionID: sessionID,
		Seq:       proto.PackDataSeq(blockID, pktIdx),
	}.Marshal(hdr)
	return tr.Send(transport.Frame{Data: append(hdr, encrypted...)})
}

// sendFECRepair encrypts one repair symbol and sends it as a FrameRepair packet to the server.
// Called by the FEC pipe's sendRepair callback.
func sendFECRepair(tr *transport.UDPTransport, sessionID uint32, hubID uint16, cipher *crypto.Cipher, blockID uint32, repairIdx, blockK, blockR uint8, data []byte) error {
	encrypted, err := cipher.Seal(data)
	if err != nil {
		return err
	}
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{
		Type:      proto.FrameRepair,
		HubID:     hubID,
		SessionID: sessionID,
		Seq:       proto.PackRepairSeq(blockID, repairIdx, blockK, blockR),
	}.Marshal(hdr)
	return tr.Send(transport.Frame{Data: append(hdr, encrypted...)})
}

// sendPing sends a keepalive ping to the server. Errors are ignored because
// pings are best-effort; the reconnect loop handles real connectivity loss.
func sendPing(tr *transport.UDPTransport, sessionID uint32, hubID uint16) {
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FramePing, HubID: hubID, SessionID: sessionID}.Marshal(hdr)
	_ = tr.Send(transport.Frame{Data: hdr})
}
