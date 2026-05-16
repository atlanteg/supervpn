// supervpn-server — L2 VPN server with multi-hub support.
// Listens on UDP (primary) and TCP+TLS (fallback) for client connections.
// Each Hub is an independent L2 broadcast domain (transparent Ethernet switch).
//
// Usage:
//
//	supervpn-server [-config /etc/supervpn/server.toml]
//	supervpn-server hashpw <password>
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/atlanteg/supervpn/internal/auth"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/crypto"
	"github.com/atlanteg/supervpn/internal/fec"
	"github.com/atlanteg/supervpn/internal/hub"
	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
	"github.com/atlanteg/supervpn/internal/update"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", config.DefaultServerConfigPath(), "config file")
	flag.Parse()

	if len(os.Args) >= 2 && os.Args[1] == "hashpw" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: supervpn-server hashpw <password>")
			os.Exit(1)
		}
		wireHex := auth.WireHash(os.Args[2])
		h, err := auth.HashPassword(wireHex)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(h)
		return
	}

	cfg, err := config.LoadServerConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	update.CheckAndUpdate(version, update.AssetServer, nil)

	log.Printf("supervpn-server %s starting: UDP=%s hubs=%d", version, cfg.Listen, len(cfg.Hubs))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mgr := hub.NewManager()
	for _, hcfg := range cfg.Hubs {
		h := hub.New(hcfg.ID, hcfg.Name)
		mgr.Add(h)
		h.StartMACPurge(ctx)
		log.Printf("hub %d %q ready", hcfg.ID, hcfg.Name)
	}

	srv := &Server{
		cfg:       cfg,
		manager:   mgr,
		sessions:  make(map[uint32]*Session),
		kicked:    make(map[string]time.Time),
		startTime: time.Now(),
	}
	srv.checkUpdateAssets()
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
	log.Println("shutdown complete")
}

// Session holds the per-client state for an authenticated VPN session.
type Session struct {
	ID           uint32
	HubID        uint16
	Login        string
	RemoteAddr   string    // IP:port of the client
	Mode         string    // "udp" or "tls"
	ConnectedAt  time.Time // when auth completed
	sendRaw      func([]byte) error
	sendRaw2     func([]byte) error // secondary send path; nil = no secondary
	secondaryAddr string            // remote addr of secondary path (for logging)
	closeConn    func()             // closes the underlying transport (no-op for UDP)
	closeConn2   func()             // closes secondary TLS conn (nil = no secondary)
	cipher       *crypto.Cipher
	replay       crypto.ReplayWindow
	pipe         *fec.Pipe
	cancel       context.CancelFunc // cancels per-session goroutines (e.g. FEC flush)
	lastSeen     time.Time
	framesRx     int64 // frames received from this client and forwarded to hub
	framesTx     int64 // frames sent to this client from hub
	hubSendCalls int64 // times hub called client.Send (pre-FEC); if >0 and framesTx=0, pipe/cipher bug
	mu           sync.Mutex
}

const kickBlockDuration = 5 * time.Minute

// Server handles auth, data forwarding, and ping/pong over UDP and TLS/TCP.
type Server struct {
	cfg           *config.ServerConfig
	manager       *hub.Manager
	conn          *net.UDPConn
	conn2         *net.UDPConn      // secondary UDP listener on port+1
	sessions      map[uint32]*Session
	kicked        map[string]time.Time // login → blocked until; prevents immediate reconnect after kick
	mu            sync.RWMutex
	startTime     time.Time
	tcpListenerUp bool             // true once the TLS/TCP listener successfully binds
	updateAssets  map[string]int64 // asset name → size in bytes (0 = missing)
}

// Run starts the UDP listener (and TLS/TCP + status listeners if configured).
func (s *Server) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	log.Printf("listening UDP %s", s.cfg.Listen)

	if sec2Addr := deriveSecondaryAddr(s.cfg.Listen); sec2Addr != "" {
		if sec2UDPAddr, e := net.ResolveUDPAddr("udp", sec2Addr); e == nil {
			if conn2, e := net.ListenUDP("udp", sec2UDPAddr); e == nil {
				s.conn2 = conn2
				log.Printf("listening UDP secondary %s", sec2Addr)
				go s.runSecondaryUDP(ctx, conn2)
			} else {
				log.Printf("secondary UDP listen %s: %v", sec2Addr, e)
			}
		}
	}

	if s.cfg.ListenTCP != "" {
		go s.runTCPListener(ctx)
		go s.runTCPListener2(ctx)
	}
	if s.cfg.StatusListen != "" {
		go s.runStatusServer(ctx)
	}

	go s.cleanupLoop(ctx)

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			conn.Close()
			return ctx.Err()
		default:
		}
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		ra := raddr
		go s.handlePacket(ctx, pkt, func(p []byte) error {
			_, err := s.conn.WriteToUDP(p, ra)
			return err
		}, ra.String(), "udp", func() {}, false)
	}
}

func (s *Server) runTCPListener(ctx context.Context) {
	tlsCfg, err := transport.NewServerTLSConfig(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		log.Printf("TLS config error, TCP listener disabled: %v", err)
		return
	}
	ln, err := transport.ListenTLS(s.cfg.ListenTCP, tlsCfg)
	if err != nil {
		log.Printf("TLS listen %s FAILED: %v", s.cfg.ListenTCP, err)
		return
	}
	s.mu.Lock()
	s.tcpListenerUp = true
	s.mu.Unlock()
	log.Printf("listening TLS/TCP %s", s.cfg.ListenTCP)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("TLS accept error: %v", err)
				continue
			}
		}
		go s.handleTCPConn(ctx, conn)
	}
}

func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("TCP accept from %s", remoteAddr)

	tr, err := transport.AcceptTLS(conn)
	if err != nil {
		log.Printf("TCP %s: TLS handshake failed: %v", remoteAddr, err)
		return
	}
	log.Printf("TCP %s: TLS handshake ok", remoteAddr)
	defer func() {
		tr.Close()
		log.Printf("TCP %s: connection closed", remoteAddr)
	}()

	sendReply := func(pkt []byte) error {
		return tr.Send(transport.Frame{Data: pkt})
	}
	closeConn := func() { tr.Close() }

	var sessionID uint32
	for {
		f, err := tr.Recv(ctx)
		if err != nil {
			if sessionID != 0 {
				s.removeSession(sessionID)
				log.Printf("TCP %s: session %d lost: %v", remoteAddr, sessionID, err)
			} else {
				log.Printf("TCP %s: pre-auth error (TLS or read): %v", remoteAddr, err)
			}
			return
		}
		if sessionID == 0 {
			log.Printf("TCP %s: received %d bytes (pre-auth)", remoteAddr, len(f.Data))
		}
		if sid := s.handlePacket(ctx, f.Data, sendReply, remoteAddr, "tls", closeConn, false); sid != 0 {
			sessionID = sid
			log.Printf("TCP %s: session %d established", remoteAddr, sessionID)
		}
	}
}

// handlePacket dispatches one wire packet. secondary=true means the packet arrived
// on the secondary listener (port+1); auth is skipped and the path is auto-registered.
// Returns new session ID on auth, 0 otherwise.
func (s *Server) handlePacket(ctx context.Context, pkt []byte, sendReply func([]byte) error, remoteAddr, mode string, closeConn func(), secondary bool) uint32 {
	hdr, ok := proto.ParseHeader(pkt)
	if !ok {
		return 0
	}
	payload := pkt[proto.HeaderSize:]
	switch hdr.Type {
	case proto.FrameAuth:
		if !secondary {
			return s.handleAuth(ctx, payload, sendReply, remoteAddr, mode, closeConn)
		}
	case proto.FrameData:
		s.handleData(hdr, payload, sendReply, remoteAddr, secondary)
	case proto.FrameRepair:
		s.handleRepair(hdr, payload, sendReply, remoteAddr, secondary)
	case proto.FrameJoin:
		if secondary {
			s.handleJoin(hdr, sendReply, remoteAddr, closeConn)
		}
	case proto.FramePing:
		s.handlePing(hdr, sendReply)
	}
	return 0
}

func (s *Server) handleAuth(ctx context.Context, payload []byte, sendReply func([]byte) error, remoteAddr, mode string, closeConn func()) uint32 {
	replyError := func(msg string) {
		ae := proto.AuthError{Message: msg}
		p := append([]byte{proto.AuthMsgError}, ae.Marshal()...)
		hdr := make([]byte, proto.HeaderSize)
		proto.Header{Type: proto.FrameAuth}.Marshal(hdr)
		_ = sendReply(append(hdr, p...))
	}

	if len(payload) == 0 || payload[0] != proto.AuthMsgHello {
		return 0
	}
	hello, err := proto.ParseAuthHello(payload[1:])
	if err != nil {
		replyError("malformed auth request")
		return 0
	}
	h, ok := s.manager.Get(hello.HubID)
	if !ok {
		replyError("hub not found")
		return 0
	}

	var storedHash string
	for _, hcfg := range s.cfg.Hubs {
		if hcfg.ID == hello.HubID {
			for _, u := range hcfg.Users {
				if u.Login == hello.Login {
					storedHash = u.PasswordHash
				}
			}
		}
	}
	if storedHash == "" {
		replyError("invalid credentials")
		return 0
	}

	wireHex := hex.EncodeToString(hello.PWHash[:])
	if err := auth.CheckPassword(wireHex, storedHash); err != nil {
		replyError("invalid credentials")
		return 0
	}

	s.mu.RLock()
	blockedUntil, isBlocked := s.kicked[hello.Login]
	s.mu.RUnlock()
	if isBlocked && time.Now().Before(blockedUntil) {
		replyError(fmt.Sprintf("kicked: reconnect after %s", blockedUntil.UTC().Format(time.RFC3339)))
		return 0
	}

	// Evict any existing session for this login@hub (stale UDP session or rapid reconnect).
	// This ensures only one active session per user, prevents hub from holding two entries,
	// and makes old sessions disappear immediately instead of waiting 90 s for timeout.
	s.mu.Lock()
	var stale []*Session
	for id, ex := range s.sessions {
		if ex.Login == hello.Login && ex.HubID == hello.HubID {
			stale = append(stale, ex)
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()
	for _, ex := range stale {
		if ex.cancel != nil {
			ex.cancel()
		}
		if h2, ok2 := s.manager.Get(ex.HubID); ok2 {
			h2.Leave(ex.ID)
		}
		ex.closeConn() // no-op for UDP; closes TCP connection immediately
		ex.mu.Lock()
		cc2 := ex.closeConn2
		ex.mu.Unlock()
		if cc2 != nil {
			cc2()
		}
		log.Printf("evicted stale session %d (%s@hub%d) on reconnect", ex.ID, ex.Login, ex.HubID)
	}

	sessionID := s.newSessionID()
	hubNetName := fmt.Sprintf("hub%d", hello.HubID)
	key, err := crypto.DeriveKey(wireHex, hubNetName, "server", hello.Login)
	if err != nil {
		replyError("internal error")
		return 0
	}
	cipher, err := crypto.NewCipher(key, sessionID)
	if err != nil {
		replyError("internal error")
		return 0
	}

	fecCfg := s.cfg.FEC.WithDefaults()
	now := time.Now()

	sess := &Session{
		ID:          sessionID,
		HubID:       hello.HubID,
		Login:       hello.Login,
		RemoteAddr:  remoteAddr,
		Mode:        mode,
		ConnectedAt: now,
		sendRaw:     sendReply,
		closeConn:   closeConn,
		cipher:      cipher,
		lastSeen:    now,
	}

	pipe, err := fec.NewPipe(
		fecCfg.K,
		fecCfg.R,
		fecCfg.RepairDelayDuration(),
		func(blockID uint32, pktIdx uint16, data []byte) error {
			return s.sendFECData(sess, blockID, pktIdx, data)
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			return s.sendFECRepair(sess, blockID, repairIdx, uint8(fecCfg.K), uint8(fecCfg.R), data)
		},
	)
	if err != nil {
		replyError("internal error")
		return 0
	}
	sess.pipe = pipe

	// Per-session context used to stop the FEC stale-block flush goroutine.
	// The server's root ctx is the parent so the goroutine also exits on shutdown.
	sCtx, sCancel := context.WithCancel(ctx)
	sess.cancel = sCancel

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.mu.Unlock()

	client := &hub.Client{
		SessionID: sessionID,
		Login:     hello.Login,
		Send: func(frame []byte) error {
			sess.mu.Lock()
			sess.hubSendCalls++
			sess.mu.Unlock()
			return sess.pipe.Send(frame)
		},
	}
	h.Join(client)

	// Flush stale FEC blocks every 50ms; delivers buffered frames that are stuck
	// behind an unrecoverable gap (mid-block loss burst).
	pipe.StartFlush(sCtx, 200*time.Millisecond, func(frame []byte) {
		if len(frame) < 14 {
			return
		}
		sess.mu.Lock()
		sess.framesRx++
		sess.mu.Unlock()
		h.Forward(sessionID, frame)
	})

	log.Printf("auth ok: %s@hub%d session=%d addr=%s mode=%s fec=K%d/R%d delay=%dms",
		hello.Login, hello.HubID, sessionID, remoteAddr, mode, fecCfg.K, fecCfg.R, fecCfg.RepairDelay)

	okMsg := proto.AuthOK{SessionID: sessionID}
	p := append([]byte{proto.AuthMsgOK}, okMsg.Marshal()...)
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameAuth}.Marshal(hdr)
	_ = sendReply(append(hdr, p...))
	return sessionID
}

func (s *Server) handleData(hdr proto.Header, payload []byte, sendReply func([]byte) error, remoteAddr string, secondary bool) {
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	sess.lastSeen = time.Now()
	sess.mu.Unlock()

	frame, err := sess.cipher.Open(payload, &sess.replay)
	if err != nil {
		return
	}

	if secondary {
		sess.mu.Lock()
		if sess.sendRaw2 == nil {
			sess.sendRaw2 = sendReply
			sess.secondaryAddr = remoteAddr
			log.Printf("session %d: secondary UDP path registered from %s", sess.ID, remoteAddr)
		}
		sess.mu.Unlock()
	}

	blockID, pktIdx := proto.UnpackDataSeq(hdr.Seq)
	recovered, err := sess.pipe.RecvData(blockID, pktIdx, frame)
	if err != nil || recovered == nil {
		return
	}
	h, ok := s.manager.Get(sess.HubID)
	if !ok {
		return
	}
	for _, f := range recovered {
		if len(f) >= 14 {
			sess.mu.Lock()
			sess.framesRx++
			sess.mu.Unlock()
			h.Forward(hdr.SessionID, f)
		}
	}
}

func (s *Server) handleRepair(hdr proto.Header, payload []byte, sendReply func([]byte) error, remoteAddr string, secondary bool) {
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	frame, err := sess.cipher.Open(payload, &sess.replay)
	if err != nil {
		return
	}

	if secondary {
		sess.mu.Lock()
		if sess.sendRaw2 == nil {
			sess.sendRaw2 = sendReply
			sess.secondaryAddr = remoteAddr
			log.Printf("session %d: secondary UDP path registered from %s", sess.ID, remoteAddr)
		}
		sess.mu.Unlock()
	}

	blockID, repairIdx, blockK, blockR := proto.UnpackRepairSeq(hdr.Seq)
	recovered, err := sess.pipe.RecvRepair(blockID, repairIdx, blockK, blockR, frame)
	if err != nil || recovered == nil {
		return
	}
	h, ok := s.manager.Get(sess.HubID)
	if !ok {
		return
	}
	for _, f := range recovered {
		if len(f) >= 14 {
			sess.mu.Lock()
			sess.framesRx++
			sess.mu.Unlock()
			h.Forward(hdr.SessionID, f)
		}
	}
}

func (s *Server) handlePing(hdr proto.Header, sendReply func([]byte) error) {
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if ok {
		sess.mu.Lock()
		sess.lastSeen = time.Now()
		sess.mu.Unlock()
	}
	pong := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FramePong, SessionID: hdr.SessionID}.Marshal(pong)
	_ = sendReply(pong)
}

func (s *Server) sendFECData(sess *Session, blockID uint32, pktIdx uint16, frame []byte) error {
	encrypted, err := sess.cipher.Seal(frame)
	if err != nil {
		return err
	}
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{
		Type:      proto.FrameData,
		HubID:     sess.HubID,
		SessionID: sess.ID,
		Seq:       proto.PackDataSeq(blockID, pktIdx),
	}.Marshal(hdr)
	pkt := append(hdr, encrypted...)
	sess.mu.Lock()
	sess.framesTx++
	send2 := sess.sendRaw2
	sess.mu.Unlock()
	err = sess.sendRaw(pkt)
	if send2 != nil {
		_ = send2(pkt)
	}
	return err
}

func (s *Server) sendFECRepair(sess *Session, blockID uint32, repairIdx, blockK, blockR uint8, data []byte) error {
	encrypted, err := sess.cipher.Seal(data)
	if err != nil {
		return err
	}
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{
		Type:      proto.FrameRepair,
		HubID:     sess.HubID,
		SessionID: sess.ID,
		Seq:       proto.PackRepairSeq(blockID, repairIdx, blockK, blockR),
	}.Marshal(hdr)
	pkt := append(hdr, encrypted...)
	sess.mu.Lock()
	send2 := sess.sendRaw2
	sess.mu.Unlock()
	err = sess.sendRaw(pkt)
	if send2 != nil {
		_ = send2(pkt)
	}
	return err
}

func (s *Server) newSessionID() uint32 {
	var b [4]byte
	rand.Read(b[:])
	id := binary.BigEndian.Uint32(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

func (s *Server) removeSession(id uint32) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if ok {
		if sess.cancel != nil {
			sess.cancel()
		}
		sess.mu.Lock()
		cc2 := sess.closeConn2
		sess.mu.Unlock()
		if cc2 != nil {
			cc2()
		}
		if h, ok2 := s.manager.Get(sess.HubID); ok2 {
			h.Leave(id)
		}
		log.Printf("session %d closed (%s)", id, sess.Login)
	}
}

func (s *Server) cleanupLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.cleanupSessions()
		}
	}
}

func (s *Server) cleanupSessions() {
	deadline := time.Now().Add(-60 * time.Second)
	now := time.Now()
	s.mu.Lock()
	for id, sess := range s.sessions {
		sess.mu.Lock()
		stale := sess.lastSeen.Before(deadline)
		sess.mu.Unlock()
		if stale {
			delete(s.sessions, id)
			if sess.cancel != nil {
				sess.cancel()
			}
			sess.mu.Lock()
			cc2 := sess.closeConn2
			sess.mu.Unlock()
			if cc2 != nil {
				cc2()
			}
			if h, ok := s.manager.Get(sess.HubID); ok {
				h.Leave(id)
			}
			log.Printf("session %d timed out (%s)", id, sess.Login)
		}
	}
	for login, until := range s.kicked {
		if now.After(until) {
			delete(s.kicked, login)
		}
	}
	s.mu.Unlock()
}

// ── Dual-path (secondary listener) ───────────────────────────────────────────

// deriveSecondaryAddr returns host:port+1 for the given host:port address.
func deriveSecondaryAddr(addr string) string {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port+1))
}

// runSecondaryUDP reads from the secondary UDP socket (port+1) and routes packets
// through handlePacket with secondary=true, enabling auto-registration of the
// client's secondary source address as sess.sendRaw2.
func (s *Server) runSecondaryUDP(ctx context.Context, conn *net.UDPConn) {
	defer conn.Close()
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("secondary UDP: read error: %v", err)
				return
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		ra := raddr
		go s.handlePacket(ctx, pkt, func(p []byte) error {
			_, err := conn.WriteToUDP(p, ra)
			return err
		}, ra.String(), "udp2", func() {}, true)
	}
}

// runTCPListener2 starts a secondary TLS/TCP listener on ListenTCP+1.
// Clients connect here as a second path; the first packet must be FrameJoin
// carrying the session ID obtained from the primary auth.
func (s *Server) runTCPListener2(ctx context.Context) {
	sec2Addr := deriveSecondaryAddr(s.cfg.ListenTCP)
	if sec2Addr == "" {
		return
	}
	tlsCfg, err := transport.NewServerTLSConfig(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		log.Printf("TLS secondary: config error: %v", err)
		return
	}
	ln, err := transport.ListenTLS(sec2Addr, tlsCfg)
	if err != nil {
		log.Printf("TLS secondary listen %s FAILED: %v", sec2Addr, err)
		return
	}
	log.Printf("listening TLS/TCP secondary %s", sec2Addr)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("TLS secondary accept error: %v", err)
				continue
			}
		}
		go s.handleTCPConn2(ctx, conn)
	}
}

// handleTCPConn2 manages one secondary TLS connection.
// It expects FrameJoin as the first packet to identify the session, then
// forwards FrameData/FrameRepair through the normal handlers.
func (s *Server) handleTCPConn2(ctx context.Context, conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	tr, err := transport.AcceptTLS(conn)
	if err != nil {
		log.Printf("TCP secondary %s: TLS handshake failed: %v", remoteAddr, err)
		return
	}
	defer tr.Close()

	sendReply := func(pkt []byte) error {
		return tr.Send(transport.Frame{Data: pkt})
	}
	closeConn := func() { tr.Close() }

	var sessionID uint32
	for {
		f, err := tr.Recv(ctx)
		if err != nil {
			if sessionID != 0 {
				s.mu.RLock()
				sess, ok := s.sessions[sessionID]
				s.mu.RUnlock()
				if ok {
					sess.mu.Lock()
					sess.sendRaw2 = nil
					sess.secondaryAddr = ""
					sess.closeConn2 = nil
					sess.mu.Unlock()
					log.Printf("TCP secondary %s: session %d secondary path lost", remoteAddr, sessionID)
				}
			}
			return
		}
		hdr, ok := proto.ParseHeader(f.Data)
		if !ok {
			continue
		}

		if sessionID == 0 {
			if hdr.Type == proto.FrameJoin && hdr.SessionID != 0 {
				s.handleJoin(hdr, sendReply, remoteAddr, closeConn)
				sessionID = hdr.SessionID
				log.Printf("TCP secondary %s: session %d registered", remoteAddr, sessionID)
			}
			continue
		}

		payload := f.Data[proto.HeaderSize:]
		switch hdr.Type {
		case proto.FrameData:
			s.handleData(hdr, payload, sendReply, remoteAddr, false)
		case proto.FrameRepair:
			s.handleRepair(hdr, payload, sendReply, remoteAddr, false)
		case proto.FramePing:
			s.handlePing(hdr, sendReply)
		}
	}
}

// handleJoin registers a TLS secondary connection as sess.sendRaw2.
func (s *Server) handleJoin(hdr proto.Header, sendReply func([]byte) error, remoteAddr string, closeConn func()) {
	if hdr.SessionID == 0 {
		return
	}
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	if sess.sendRaw2 == nil {
		sess.sendRaw2 = sendReply
		sess.secondaryAddr = remoteAddr
		sess.closeConn2 = closeConn
		log.Printf("session %d: secondary TLS path registered from %s", sess.ID, remoteAddr)
	}
	sess.mu.Unlock()
}

// ── Update mirror ────────────────────────────────────────────────────────────

// clientAssets lists every binary the server may serve as a mirror.
var clientAssets = []string{
	"supervpn-client-windows-amd64.exe",
	"supervpn-client-darwin-arm64",
	"supervpn-client-darwin-amd64",
}

// updateDir returns the resolved directory for client assets.
func (s *Server) updateDir() string {
	if s.cfg.UpdateDir != "" {
		return s.cfg.UpdateDir
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "dist")
	}
	return "dist"
}

// checkUpdateAssets verifies that client binaries are present in updateDir.
// Missing files are downloaded from the GitHub release matching the server's
// own version tag. Dev builds skip auto-download. Populates s.updateAssets.
func (s *Server) checkUpdateAssets() {
	dir := s.updateDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("update mirror: cannot create dir %s: %v", dir, err)
	}

	canFetch := version != "dev"
	if !canFetch {
		log.Printf("update mirror: dev build — skipping auto-download of client binaries")
	}

	assets := make(map[string]int64, len(clientAssets))
	for _, name := range clientAssets {
		path := filepath.Join(dir, name)
		if fi, err := os.Stat(path); err == nil {
			log.Printf("update mirror: ok  %s  (%d bytes)", name, fi.Size())
			assets[name] = fi.Size()
			continue
		}
		if !canFetch {
			log.Printf("update mirror: missing  %s", name)
			continue
		}
		log.Printf("update mirror: downloading  %s  (release %s) ...", name, version)
		if err := update.FetchAsset(version, name, path); err != nil {
			log.Printf("update mirror: download %s failed: %v", name, err)
			continue
		}
		fi, _ := os.Stat(path)
		log.Printf("update mirror: ready  %s  (%d bytes)", name, fi.Size())
		assets[name] = fi.Size()
	}

	s.mu.Lock()
	s.updateAssets = assets
	s.mu.Unlock()

	if s.cfg.StatusListen != "" {
		available := 0
		for _, sz := range assets {
			if sz > 0 {
				available++
			}
		}
		mirrorURL := s.mirrorURL()
		if available == len(clientAssets) {
			log.Printf("update mirror ready — clients: update_mirrors = [\"%s\"]", mirrorURL)
		} else {
			log.Printf("update mirror: %d/%d assets available at %s", available, len(clientAssets), mirrorURL)
		}
	}
}

// mirrorURL returns the client-facing base URL for the update mirror.
// Uses the host from status_listen, with two adjustments:
//   - wildcard (0.0.0.0 / ::) → replaced with the host from cfg.Listen
//   - loopback (127.0.0.1 / ::1) → replaced with <your_server_ip> and a warning
func (s *Server) mirrorURL() string {
	host, port, err := net.SplitHostPort(s.cfg.StatusListen)
	if err != nil {
		return "http://" + s.cfg.StatusListen + "/update"
	}
	switch host {
	case "", "0.0.0.0", "::":
		// Wildcard — derive host from the UDP listen address.
		if udpHost, _, e := net.SplitHostPort(s.cfg.Listen); e == nil &&
			udpHost != "" && udpHost != "0.0.0.0" && udpHost != "::" {
			host = udpHost
		} else {
			host = "<your_server_ip>"
		}
	case "127.0.0.1", "::1":
		log.Printf("update mirror: WARNING: status_listen is bound to loopback (%s) — "+
			"clients on other machines cannot reach the mirror; "+
			"set status_listen = \"0.0.0.0:%s\" to expose it", s.cfg.StatusListen, port)
		host = "<your_server_ip>"
	}
	return fmt.Sprintf("http://%s:%s/update", host, port)
}

// handleUpdateAsset serves a client binary from updateDir.
// Only names in clientAssets are allowed — path traversal is impossible.
func (s *Server) handleUpdateAsset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/update/")
	allowed := false
	for _, a := range clientAssets {
		if name == a {
			allowed = true
			break
		}
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.updateDir(), name))
}

// ── Status HTTP API ──────────────────────────────────────────────────────────

type statusResponse struct {
	Version         string            `json:"version"`
	Uptime          string            `json:"uptime"`
	UDPListen       string            `json:"udp_listen"`
	TCPListen       string            `json:"tcp_listen,omitempty"`
	TCPListenerUp   bool              `json:"tcp_listener_up"`
	Hubs            []hubStatus       `json:"hubs"`
	Blocked         map[string]string `json:"blocked,omitempty"` // login → blocked_until (RFC3339)
	UpdateMirror    *mirrorStatus     `json:"update_mirror,omitempty"`
}

type mirrorStatus struct {
	URL    string            `json:"url"`
	Assets map[string]string `json:"assets"` // asset name → "ok (N bytes)" | "missing"
}

type hubStatus struct {
	ID       uint16          `json:"id"`
	Name     string          `json:"name"`
	Clients  []clientStatus  `json:"clients"`
	MACTable []macTableEntry `json:"mac_table"`
}

type macTableEntry struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip,omitempty"`
	Login     string `json:"login,omitempty"`
	SessionID uint32 `json:"session_id"`
	ExpiresIn string `json:"expires_in"`
}

type clientStatus struct {
	SessionID   uint32 `json:"session_id"`
	Login       string `json:"login"`
	RemoteAddr  string `json:"remote_addr"`
	Mode        string `json:"mode"`
	ConnectedAt string `json:"connected_at"`
	LastSeen    string `json:"last_seen"`
	Duration    string `json:"duration"`
	FramesRx     int64 `json:"frames_rx"`
	FramesTx     int64 `json:"frames_tx"`
	HubSendCalls int64 `json:"hub_send_calls"`
}

func (s *Server) runStatusServer(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/api/hubs/", s.handleAPI)    // POST /api/hubs/{id}/kick/{session}
	mux.HandleFunc("/update/version", s.handleUpdateVersion) // mirror: plain-text current version
	mux.HandleFunc("/update/", s.handleUpdateAsset)          // mirror: client binary download

	srv := &http.Server{Addr: s.cfg.StatusListen, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Printf("status API on http://%s/status", s.cfg.StatusListen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("status server error: %v", err)
	}
}

// handleAPI dispatches management actions.
// Currently supports: POST /api/hubs/{hub_id}/kick/{session_id}
func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	// Path: /api/hubs/{hub_id}/kick/{session_id}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 4 && parts[0] == "api" && parts[1] == "hubs" && parts[3] == "kick" {
		http.Error(w, "use POST /api/hubs/{id}/kick/{session_id}", http.StatusBadRequest)
		return
	}
	if len(parts) != 5 || parts[0] != "api" || parts[1] != "hubs" || parts[3] != "kick" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	sid64, err := strconv.ParseUint(parts[4], 10, 32)
	if err != nil {
		http.Error(w, "invalid session_id", http.StatusBadRequest)
		return
	}
	sessionID := uint32(sid64)

	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	if ok {
		delete(s.sessions, sessionID)
		s.kicked[sess.Login] = time.Now().Add(kickBlockDuration)
	}
	s.mu.Unlock()

	if !ok {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}

	// Close transport (no-op for UDP; closes TCP connection immediately).
	sess.closeConn()
	sess.mu.Lock()
	cc2 := sess.closeConn2
	sess.mu.Unlock()
	if cc2 != nil {
		cc2()
	}

	if h, ok2 := s.manager.Get(sess.HubID); ok2 {
		h.Leave(sessionID)
	}
	log.Printf("kick: session %d (%s@hub%d) blocked for %s", sessionID, sess.Login, sess.HubID, kickBlockDuration)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","session_id":%d,"login":%q}`, sessionID, sess.Login)
}

func (s *Server) handleUpdateVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, version)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now()

	// Build session index by hub.
	type sessSnapshot struct {
		SessionID    uint32
		Login        string
		RemoteAddr   string
		Mode         string
		ConnectedAt  time.Time
		LastSeen     time.Time
		FramesRx     int64
		FramesTx     int64
		HubSendCalls int64
	}
	byHub := make(map[uint16][]sessSnapshot)

	s.mu.RLock()
	for _, sess := range s.sessions {
		sess.mu.Lock()
		snap := sessSnapshot{
			SessionID:    sess.ID,
			Login:        sess.Login,
			RemoteAddr:   sess.RemoteAddr,
			Mode:         sess.Mode,
			ConnectedAt:  sess.ConnectedAt,
			LastSeen:     sess.lastSeen,
			FramesRx:     sess.framesRx,
			FramesTx:     sess.framesTx,
			HubSendCalls: sess.hubSendCalls,
		}
		sess.mu.Unlock()
		byHub[sess.HubID] = append(byHub[sess.HubID], snap)
	}
	s.mu.RUnlock()

	// Build hub list from config (preserves order, shows empty hubs too).
	hubs := make([]hubStatus, 0, len(s.cfg.Hubs))
	for _, hcfg := range s.cfg.Hubs {
		hs := hubStatus{ID: hcfg.ID, Name: hcfg.Name, Clients: []clientStatus{}, MACTable: []macTableEntry{}}
		for _, snap := range byHub[hcfg.ID] {
			hs.Clients = append(hs.Clients, clientStatus{
				SessionID:    snap.SessionID,
				Login:        snap.Login,
				RemoteAddr:   snap.RemoteAddr,
				Mode:         snap.Mode,
				ConnectedAt:  snap.ConnectedAt.UTC().Format(time.RFC3339),
				LastSeen:     snap.LastSeen.UTC().Format(time.RFC3339),
				Duration:     now.Sub(snap.ConnectedAt).Truncate(time.Second).String(),
				FramesRx:     snap.FramesRx,
				FramesTx:     snap.FramesTx,
				HubSendCalls: snap.HubSendCalls,
			})
		}
		if h, ok := s.manager.Get(hcfg.ID); ok {
			for _, rec := range h.MACTableSnapshot() {
				e := macTableEntry{
					MAC:       rec.MAC.String(),
					Login:     rec.Login,
					SessionID: rec.SessionID,
					ExpiresIn: rec.ExpiresIn.String(),
				}
				if rec.IP != nil {
					e.IP = rec.IP.String()
				}
				hs.MACTable = append(hs.MACTable, e)
			}
		}
		hubs = append(hubs, hs)
	}

	s.mu.RLock()
	blocked := make(map[string]string, len(s.kicked))
	for login, until := range s.kicked {
		if now.Before(until) {
			blocked[login] = until.UTC().Format(time.RFC3339)
		}
	}
	s.mu.RUnlock()

	s.mu.RLock()
	tcpUp := s.tcpListenerUp
	s.mu.RUnlock()

	var mirror *mirrorStatus
	if s.cfg.StatusListen != "" {
		s.mu.RLock()
		assets := s.updateAssets
		s.mu.RUnlock()
		if assets != nil {
			assetInfo := make(map[string]string, len(assets))
			for _, name := range clientAssets {
				if sz := assets[name]; sz > 0 {
					assetInfo[name] = fmt.Sprintf("ok (%d bytes)", sz)
				} else {
					assetInfo[name] = "missing"
				}
			}
			mirror = &mirrorStatus{
				URL:    s.mirrorURL(),
				Assets: assetInfo,
			}
		}
	}

	resp := statusResponse{
		Version:       version,
		Uptime:        now.Sub(s.startTime).Truncate(time.Second).String(),
		UDPListen:     s.cfg.Listen,
		TCPListen:     s.cfg.ListenTCP,
		TCPListenerUp: tcpUp,
		Hubs:          hubs,
		UpdateMirror:  mirror,
	}
	if len(blocked) > 0 {
		resp.Blocked = blocked
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(resp)
}
