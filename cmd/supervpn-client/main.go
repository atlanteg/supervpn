// supervpn-client — L2 VPN client with transparent 169.254.0.0/16 bridge.
// Detects local interfaces with link-local addresses and bridges them to
// the supervpn server hub via UDP (primary) or TLS/TCP (fallback).
//
// Transport selection:
//   - On each connect attempt, UDP is probed first (knock×N → auth, 5s timeout).
//   - If all UDP attempts fail, falls back to TLS/TCP on server_tcp.
//   - When connected via TLS, a background timer retries UDP every 5 minutes.
//
// Usage:
//
//	supervpn-client -server host:5555 -hub 1 -login user -password pass
//	supervpn-client -config /etc/supervpn/client.toml
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/crypto"
	"github.com/atlanteg/supervpn/internal/fec"
	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

var version = "dev"

// sessionState holds the current connection state for the status API.
var sessionState = &clientSessionState{
	startTime: time.Now(),
	state:     "starting",
}

type clientSessionState struct {
	mu          sync.RWMutex
	startTime   time.Time
	state       string    // "starting" | "connecting" | "connected" | "reconnecting"
	mode        string    // "udp" | "tls" | ""
	server      string    // address actually connected to
	hubID       uint16
	login       string
	sessionID   uint32
	connectedAt time.Time
}

func (cs *clientSessionState) setConnecting() {
	cs.mu.Lock()
	cs.state = "connecting"
	cs.mode = ""
	cs.server = ""
	cs.sessionID = 0
	cs.connectedAt = time.Time{}
	cs.mu.Unlock()
}

func (cs *clientSessionState) setConnected(mode, server string, hubID uint16, login string, sessionID uint32) {
	cs.mu.Lock()
	cs.state = "connected"
	cs.mode = mode
	cs.server = server
	cs.hubID = hubID
	cs.login = login
	cs.sessionID = sessionID
	cs.connectedAt = time.Now()
	cs.mu.Unlock()
}

func (cs *clientSessionState) setReconnecting() {
	cs.mu.Lock()
	cs.state = "reconnecting"
	cs.mode = ""
	cs.server = ""
	cs.sessionID = 0
	cs.connectedAt = time.Time{}
	cs.mu.Unlock()
}

// openAdapter opens the virtual adapter for this session.
//
// Bridge mode (169.254.0.0/16 interface detected):
//   Windows — opens a tap-windows6 TAP adapter (L2, Ethernet frames).
//             The TAP adapter must be bridged with the physical NIC via
//             Windows Network Bridge or Hyper-V (see deploy/setup-bridge-*.ps1).
//   Linux   — opens a kernel TAP device (L2, Ethernet frames).
//   macOS   — opens a BPF device bound directly to the physical NIC (L2, Ethernet frames).
//             Requires root.
//
// Direct mode (no 169.254 interface):
//   All platforms — opens a TUN adapter (WinTun on Windows, utun on macOS).
//   Assign an IP to the adapter after startup to reach other hub peers.
func openAdapter(cfg config.ClientConfig) (bridge.Interface, bridge.Framer, error) {
	ifaces, err := bridge.DetectLinkLocal()
	if err != nil {
		return bridge.Interface{}, nil, fmt.Errorf("detect interfaces: %w", err)
	}

	// Never bridge the VPN adapter itself.
	// On Windows, supervpn-tap gets a 169.254 APIPA address when no IP is assigned;
	// without this filter the client would bridge its own VPN adapter and create a loop.
	bc := cfg.Bridge.WithDefaults()
	tunName := cfg.TunName
	if tunName == "" {
		tunName = "supervpn"
	}
	var physical []bridge.Interface
	for _, iface := range ifaces {
		if iface.Name == bc.TapName || iface.Name == tunName {
			log.Printf("bridge: ignoring own VPN adapter %q", iface.Name)
			continue
		}
		physical = append(physical, iface)
	}

	if len(physical) > 0 {
		return openBridgeAdapter(cfg, physical[0])
	}
	return openDirectAdapter(cfg)
}

func openBridgeAdapter(cfg config.ClientConfig, detected bridge.Interface) (bridge.Interface, bridge.Framer, error) {
	bc := cfg.Bridge // already has defaults applied by LoadClientConfig

	// On Windows, OpenBridge opens the named TAP adapter (tap-windows6).
	// On macOS, OpenBridge opens a BPF device on the detected physical NIC directly.
	// On Linux, OpenBridge opens a kernel TAP device.
	adapterName := bridgeAdapterName(bc.TapName, detected.Name)

	log.Printf("bridge mode: link-local interface %s (%s), adapter=%q method=%s",
		detected.Name, detected.HWAddr, adapterName, bc.SetupMethod)

	// Ensure OS-level bridge is configured before opening the TAP adapter.
	// On Windows this creates the Network Bridge if not already present.
	// On macOS/Linux this is a no-op.
	if err := ensureBridge(bc, detected.Name, adapterName); err != nil {
		log.Printf("bridge: setup warning: %v", err)
	}

	framer, err := pkgtun.OpenBridge(adapterName)
	if err != nil {
		return bridge.Interface{}, nil, fmt.Errorf("open bridge adapter %q: %w", adapterName, err)
	}

	actual := pkgtun.ActualName(framer, adapterName)
	log.Printf("bridge mode: adapter %q open", actual)

	return detected, framer, nil
}

// bridgeAdapterName returns the adapter name to pass to OpenBridge.
// On macOS (BPF), we bind directly to the physical NIC, so use detectedNIC.
// On Windows/Linux, we open a virtual TAP adapter with the configured name.
func bridgeAdapterName(tapName, detectedNIC string) string {
	return bridgeName(tapName, detectedNIC)
}

func openDirectAdapter(cfg config.ClientConfig) (bridge.Interface, bridge.Framer, error) {
	tunName := cfg.TunName
	if tunName == "" {
		tunName = "supervpn"
	}
	log.Printf("direct mode: no 169.254.x.x interface found, opening TUN %q", tunName)
	log.Printf("direct mode: assign an IP inside the hub subnet to %q after startup", tunName)

	framer, err := pkgtun.Open(tunName)
	if err != nil {
		return bridge.Interface{}, nil, fmt.Errorf("open TUN %q: %w", tunName, err)
	}

	actual := pkgtun.ActualName(framer, tunName)
	if actual != tunName {
		log.Printf("TUN assigned name: %s", actual)
	}
	return bridge.Interface{Name: actual}, framer, nil
}

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to client config file (optional)")

	var (
		serverFlag    = flag.String("server", "", "server UDP address host:port")
		serverTCPFlag = flag.String("server-tcp", "", "server TCP/TLS address host:port (empty = derive from -server)")
		hubIDFlag     = flag.Uint("hub", 1, "hub ID")
		loginFlag     = flag.String("login", "", "login")
		passwordFlag  = flag.String("password", "", "password")
		transportFlag = flag.String("transport", "", "transport mode: auto (default), udp, tcp")
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
		cfg.FEC = config.FECConfig{K: 20, R: 6}
	}
	// CLI flags override config file values.
	if *transportFlag != "" {
		cfg.Transport = *transportFlag
	}
	if *serverTCPFlag != "" {
		cfg.ServerTCP = *serverTCPFlag
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if cfg.StatusListen != "" {
		go runClientStatusServer(ctx, cfg.StatusListen)
	}

	iface, framer, err := openAdapter(cfg)
	if err != nil {
		log.Fatalf("tun: %v", err)
	}
	defer framer.Close()

	log.Printf("supervpn-client %s: server=%s hub=%d login=%s",
		version, cfg.Server, cfg.HubID, cfg.Login)

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		sessionState.setConnecting()
		err := runSession(ctx, cfg, iface, framer)
		if ctx.Err() != nil {
			return
		}
		log.Printf("session ended: %v — reconnecting in %s", err, backoff)
		sessionState.setReconnecting()
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

const (
	pingInterval    = 25 * time.Second
	keepaliveTimeout = 75 * time.Second // 3 missed pongs → reconnect
)

// runSession dials the server, authenticates, runs the bridge, and returns on error.
func runSession(ctx context.Context, cfg config.ClientConfig, iface bridge.Interface, framer bridge.Framer) error {
	tr, sessionID, sessionCipher, err := connectWithFallback(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer tr.Close()

	// Record connected state for the status API.
	sessionState.setConnected(tr.Mode(), cfg.Server, cfg.HubID, cfg.Login, sessionID)
	log.Printf("session %d active via %s", sessionID, tr.Mode())

	fecCfg := cfg.FEC.WithDefaults()

	// lastPong is updated by recvLoop each time a pong arrives.
	// Initialised to now so the first ping cycle doesn't immediately time out.
	var lastPong atomic.Int64
	lastPong.Store(time.Now().UnixNano())

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

	downstream := make(chan []byte, 64)
	b := bridge.New(iface, framer, func(frame []byte) error {
		return pipe.Send(frame)
	})

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	// When connected via TLS in auto mode, retry UDP every 5 minutes so we
	// switch back as soon as the path clears.
	if tr.Mode() == "tls" && cfg.Transport != "tcp" && cfg.Server != "" {
		go func() {
			t := time.NewTimer(5 * time.Minute)
			defer t.Stop()
			select {
			case <-t.C:
				log.Println("transport: 5-min TLS session elapsed, probing UDP")
				sessionCancel()
			case <-sessionCtx.Done():
			}
		}()
	}

	upErr := make(chan error, 1)
	go func() { upErr <- b.RunUpstream(sessionCtx) }()

	downErr := make(chan error, 1)
	go func() { downErr <- b.RunDownstream(sessionCtx, downstream) }()

	recvErr := make(chan error, 1)
	go func() {
		recvErr <- recvLoop(sessionCtx, tr, sessionID, sessionCipher, pipe, downstream, &lastPong)
	}()

	pingTick := time.NewTicker(pingInterval)
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
			since := time.Since(time.Unix(0, lastPong.Load()))
			if since > keepaliveTimeout {
				return fmt.Errorf("keepalive timeout: no pong for %s", since.Truncate(time.Second))
			}
		}
	}
}

// connectWithFallback selects a transport according to cfg.Transport:
//
//	"udp"  — UDP only; never falls back to TCP.
//	"tcp"  — TCP/TLS only; skips UDP entirely.
//	"auto" — tries UDP first (knock×N → auth, 5-second timeout per attempt),
//	         then falls back to TCP/TLS when server_tcp is configured.
func connectWithFallback(ctx context.Context, cfg config.ClientConfig) (transport.Transport, uint32, *crypto.Cipher, error) {
	mode := cfg.Transport
	if mode == "" {
		mode = "auto"
	}

	tcpAddr := resolveTCPAddr(cfg)

	if mode == "tcp" {
		if tcpAddr == "" {
			return nil, 0, nil, fmt.Errorf("transport=tcp but server_tcp is not configured (and cannot be derived from server)")
		}
		return connectTLS(ctx, cfg, tcpAddr)
	}

	// UDP path (for "auto" and "udp" modes).
	udpCfg := cfg.UDP.WithDefaults()
	for attempt := 1; attempt <= udpCfg.Attempts; attempt++ {
		if ctx.Err() != nil {
			return nil, 0, nil, ctx.Err()
		}
		log.Printf("transport: UDP attempt %d/%d (knock×%d → %s)",
			attempt, udpCfg.Attempts, udpCfg.KnockCount, cfg.Server)

		udpTr, err := transport.KnockAndDial(cfg.Server, udpCfg.KnockCount, udpCfg.KnockSize)
		if err != nil {
			log.Printf("transport: UDP dial: %v", err)
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		sid, cipher, probeErr := authenticate(probeCtx, udpTr, cfg)
		cancel()

		if probeErr == nil {
			log.Printf("transport: UDP connected (attempt %d/%d)", attempt, udpCfg.Attempts)
			return udpTr, sid, cipher, nil
		}
		udpTr.Close()
		log.Printf("transport: UDP attempt %d/%d failed: %v", attempt, udpCfg.Attempts, probeErr)
	}

	if mode == "udp" {
		return nil, 0, nil, fmt.Errorf("UDP unreachable after %d attempts (transport=udp, no TCP fallback)", udpCfg.Attempts)
	}

	// "auto": TCP/TLS fallback.
	if tcpAddr == "" {
		return nil, 0, nil, fmt.Errorf("UDP unreachable after %d attempts and server_tcp is not configured", udpCfg.Attempts)
	}
	return connectTLS(ctx, cfg, tcpAddr)
}

// resolveTCPAddr returns the TCP address to use. Uses server_tcp from config if set,
// otherwise derives host:443 from the UDP server address.
func resolveTCPAddr(cfg config.ClientConfig) string {
	if cfg.ServerTCP != "" {
		return cfg.ServerTCP
	}
	if cfg.Server == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, "443")
}

func connectTLS(ctx context.Context, cfg config.ClientConfig, tcpAddr string) (transport.Transport, uint32, *crypto.Cipher, error) {
	sni := cfg.TLS.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(tcpAddr)
		sni = host
	}
	log.Printf("transport: dialing TLS %s (sni=%s)", tcpAddr, sni)

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	tlsTr, err := transport.DialTLS(dialCtx, tcpAddr, sni)
	dialCancel()
	if err != nil {
		log.Printf("transport: TLS dial %s failed: %v", tcpAddr, err)
		return nil, 0, nil, fmt.Errorf("TLS dial: %w", err)
	}
	log.Printf("transport: TLS handshake ok, authenticating")

	authCtx, authCancel := context.WithTimeout(ctx, 10*time.Second)
	sid, cipher, err := authenticate(authCtx, tlsTr, cfg)
	authCancel()
	if err != nil {
		tlsTr.Close()
		log.Printf("transport: TLS auth failed: %v", err)
		return nil, 0, nil, fmt.Errorf("TLS auth: %w", err)
	}

	log.Printf("transport: TLS connected via %s session=%d", tcpAddr, sid)
	return tlsTr, sid, cipher, nil
}

// authenticate sends AuthHello and waits for AuthOK or AuthError.
func authenticate(ctx context.Context, tr transport.Transport, cfg config.ClientConfig) (uint32, *crypto.Cipher, error) {
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

	for {
		f, err := tr.Recv(ctx)
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

func recvLoop(ctx context.Context, tr transport.Transport, sessionID uint32, cipher *crypto.Cipher, pipe *fec.Pipe, out chan<- []byte, lastPong *atomic.Int64) error {
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
			lastPong.Store(time.Now().UnixNano())
		}
	}
}

func sendFECData(tr transport.Transport, sessionID uint32, hubID uint16, cipher *crypto.Cipher, blockID uint32, pktIdx uint16, frame []byte) error {
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

func sendFECRepair(tr transport.Transport, sessionID uint32, hubID uint16, cipher *crypto.Cipher, blockID uint32, repairIdx, blockK, blockR uint8, data []byte) error {
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

func sendPing(tr transport.Transport, sessionID uint32, hubID uint16) {
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FramePing, HubID: hubID, SessionID: sessionID}.Marshal(hdr)
	_ = tr.Send(transport.Frame{Data: hdr})
}

// ── Status HTTP API ──────────────────────────────────────────────────────────

type clientStatusResponse struct {
	Version   string          `json:"version"`
	Uptime    string          `json:"uptime"`
	State     string          `json:"state"`
	Session   *sessionDetails `json:"session,omitempty"`
}

type sessionDetails struct {
	SessionID   uint32 `json:"session_id"`
	Server      string `json:"server"`
	HubID       uint16 `json:"hub_id"`
	Login       string `json:"login"`
	Mode        string `json:"mode"`
	ConnectedAt string `json:"connected_at"`
	Duration    string `json:"duration"`
}

func runClientStatusServer(ctx context.Context, addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", handleClientStatus)
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Printf("status API on http://%s/status", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("status server error: %v", err)
	}
}

func handleClientStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	sessionState.mu.RLock()
	state := sessionState.state
	mode := sessionState.mode
	server := sessionState.server
	hubID := sessionState.hubID
	login := sessionState.login
	sessionID := sessionState.sessionID
	connectedAt := sessionState.connectedAt
	startTime := sessionState.startTime
	sessionState.mu.RUnlock()

	resp := clientStatusResponse{
		Version: version,
		Uptime:  now.Sub(startTime).Truncate(time.Second).String(),
		State:   state,
	}
	if state == "connected" {
		resp.Session = &sessionDetails{
			SessionID:   sessionID,
			Server:      server,
			HubID:       hubID,
			Login:       login,
			Mode:        mode,
			ConnectedAt: connectedAt.UTC().Format(time.RFC3339),
			Duration:    now.Sub(connectedAt).Truncate(time.Second).String(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(resp)
}
