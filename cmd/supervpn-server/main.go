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
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
	log.Println("shutdown complete")
}

// Session holds the per-client state for an authenticated VPN session.
type Session struct {
	ID          uint32
	HubID       uint16
	Login       string
	RemoteAddr  string    // IP:port of the client
	Mode        string    // "udp" or "tls"
	ConnectedAt time.Time // when auth completed
	sendRaw     func([]byte) error
	closeConn   func()             // closes the underlying transport (no-op for UDP)
	cipher      *crypto.Cipher
	replay      crypto.ReplayWindow
	pipe        *fec.Pipe
	lastSeen    time.Time
	framesRx     int64 // frames received from this client and forwarded to hub
	framesTx     int64 // frames sent to this client from hub
	hubSendCalls int64 // times hub called client.Send (pre-FEC); if >0 and framesTx=0, pipe/cipher bug
	mu           sync.Mutex
}

const kickBlockDuration = 5 * time.Minute

// Server handles auth, data forwarding, and ping/pong over UDP and TLS/TCP.
type Server struct {
	cfg       *config.ServerConfig
	manager   *hub.Manager
	conn      *net.UDPConn
	sessions  map[uint32]*Session
	kicked    map[string]time.Time // login → blocked until; prevents immediate reconnect after kick
	mu        sync.RWMutex
	startTime time.Time
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

	if s.cfg.ListenTCP != "" {
		go s.runTCPListener(ctx)
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
		go s.handlePacket(pkt, func(p []byte) error {
			_, err := s.conn.WriteToUDP(p, ra)
			return err
		}, ra.String(), "udp", func() {})
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
		log.Printf("TLS listen %s failed: %v", s.cfg.ListenTCP, err)
		return
	}
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
	tr := transport.AcceptTLS(conn)
	defer tr.Close()

	remoteAddr := conn.RemoteAddr().String()
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
			}
			return
		}
		if sid := s.handlePacket(f.Data, sendReply, remoteAddr, "tls", closeConn); sid != 0 {
			sessionID = sid
		}
	}
}

// handlePacket dispatches one wire packet. remoteAddr, mode, and closeConn are
// recorded in the session when an auth packet creates it.
// Returns new session ID on auth, 0 otherwise.
func (s *Server) handlePacket(pkt []byte, sendReply func([]byte) error, remoteAddr, mode string, closeConn func()) uint32 {
	hdr, ok := proto.ParseHeader(pkt)
	if !ok {
		return 0
	}
	payload := pkt[proto.HeaderSize:]
	switch hdr.Type {
	case proto.FrameAuth:
		return s.handleAuth(payload, sendReply, remoteAddr, mode, closeConn)
	case proto.FrameData:
		s.handleData(hdr, payload)
	case proto.FrameRepair:
		s.handleRepair(hdr, payload)
	case proto.FramePing:
		s.handlePing(hdr, sendReply)
	}
	return 0
}

func (s *Server) handleAuth(payload []byte, sendReply func([]byte) error, remoteAddr, mode string, closeConn func()) uint32 {
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
	log.Printf("auth ok: %s@hub%d session=%d addr=%s mode=%s",
		hello.Login, hello.HubID, sessionID, remoteAddr, mode)

	okMsg := proto.AuthOK{SessionID: sessionID}
	p := append([]byte{proto.AuthMsgOK}, okMsg.Marshal()...)
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameAuth}.Marshal(hdr)
	_ = sendReply(append(hdr, p...))
	return sessionID
}

func (s *Server) handleData(hdr proto.Header, payload []byte) {
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

func (s *Server) handleRepair(hdr proto.Header, payload []byte) {
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
	sess.mu.Lock()
	sess.framesTx++
	sess.mu.Unlock()
	return sess.sendRaw(append(hdr, encrypted...))
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
	return sess.sendRaw(append(hdr, encrypted...))
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
		if h, ok2 := s.manager.Get(sess.HubID); ok2 {
			h.Leave(id)
		}
		log.Printf("session %d closed (%s)", id, sess.Login)
	}
}

func (s *Server) cleanupLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
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
	deadline := time.Now().Add(-90 * time.Second)
	now := time.Now()
	s.mu.Lock()
	for id, sess := range s.sessions {
		sess.mu.Lock()
		stale := sess.lastSeen.Before(deadline)
		sess.mu.Unlock()
		if stale {
			delete(s.sessions, id)
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

// ── Status HTTP API ──────────────────────────────────────────────────────────

type statusResponse struct {
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	UDPListen string            `json:"udp_listen"`
	TCPListen string            `json:"tcp_listen,omitempty"`
	Hubs      []hubStatus       `json:"hubs"`
	Blocked   map[string]string `json:"blocked,omitempty"` // login → blocked_until (RFC3339)
}

type hubStatus struct {
	ID      uint16         `json:"id"`
	Name    string         `json:"name"`
	Clients []clientStatus `json:"clients"`
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
	mux.HandleFunc("/api/hubs/", s.handleAPI) // POST /api/hubs/{id}/kick/{session}

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

	if h, ok2 := s.manager.Get(sess.HubID); ok2 {
		h.Leave(sessionID)
	}
	log.Printf("kick: session %d (%s@hub%d) blocked for %s", sessionID, sess.Login, sess.HubID, kickBlockDuration)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","session_id":%d,"login":%q}`, sessionID, sess.Login)
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
		hs := hubStatus{ID: hcfg.ID, Name: hcfg.Name, Clients: []clientStatus{}}
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

	resp := statusResponse{
		Version:   version,
		Uptime:    now.Sub(s.startTime).Truncate(time.Second).String(),
		UDPListen: s.cfg.Listen,
		TCPListen: s.cfg.ListenTCP,
		Hubs:      hubs,
	}
	if len(blocked) > 0 {
		resp.Blocked = blocked
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(resp)
}
