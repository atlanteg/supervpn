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
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
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

	// subcommand: supervpn-server hashpw <password>
	// Generates a bcrypt hash of SHA-256-hex(password) for use in server.toml.
	// The client sends SHA-256(password) on the wire; the server converts to hex
	// and verifies against this bcrypt hash.
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

	srv := &Server{cfg: cfg, manager: mgr, sessions: make(map[uint32]*Session)}
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
	log.Println("shutdown complete")
}

// Session holds the per-client state for an authenticated VPN session.
type Session struct {
	ID       uint32
	HubID    uint16
	Login    string
	sendRaw  func([]byte) error // send a raw wire packet back to this client (UDP or TCP)
	cipher   *crypto.Cipher
	replay   crypto.ReplayWindow // per-session replay window; must not be copied after first use
	pipe     *fec.Pipe           // per-session FEC encoder/decoder
	lastSeen time.Time
	mu       sync.Mutex
}

// Server handles auth, data forwarding, and ping/pong over UDP and TLS/TCP.
type Server struct {
	cfg      *config.ServerConfig
	manager  *hub.Manager
	conn     *net.UDPConn
	sessions map[uint32]*Session
	mu       sync.RWMutex
}

// Run starts the UDP listener (and TLS/TCP listener if configured) and blocks
// until ctx is cancelled or a fatal error occurs.
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

	// Start TLS/TCP listener if configured.
	if s.cfg.ListenTCP != "" {
		go s.runTCPListener(ctx)
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
		// Capture raddr in the closure so the goroutine always replies to the
		// correct source address even if raddr changes between UDP reads.
		ra := raddr
		go s.handlePacket(pkt, func(p []byte) error {
			_, err := s.conn.WriteToUDP(p, ra)
			return err
		})
	}
}

// runTCPListener accepts TLS connections on ListenTCP and spawns a goroutine
// per connection that feeds packets into the same handlePacket pipeline.
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

// handleTCPConn reads frames from a TLS connection and dispatches them to handlePacket.
// When the connection closes, any session created on it is removed immediately.
func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	tr := transport.AcceptTLS(conn)
	defer tr.Close()

	sendReply := func(pkt []byte) error {
		return tr.Send(transport.Frame{Data: pkt})
	}

	var sessionID uint32

	for {
		f, err := tr.Recv(ctx)
		if err != nil {
			if sessionID != 0 {
				s.removeSession(sessionID)
			}
			return
		}
		if sid := s.handlePacket(f.Data, sendReply); sid != 0 {
			sessionID = sid
		}
	}
}

// handlePacket dispatches one wire packet to the appropriate handler.
// sendReply is called to send auth responses and pongs back to the originating client.
// Returns the new session ID when an auth packet creates a session; 0 otherwise.
func (s *Server) handlePacket(pkt []byte, sendReply func([]byte) error) uint32 {
	hdr, ok := proto.ParseHeader(pkt)
	if !ok {
		return 0
	}
	payload := pkt[proto.HeaderSize:]
	switch hdr.Type {
	case proto.FrameAuth:
		return s.handleAuth(payload, sendReply)
	case proto.FrameData:
		s.handleData(hdr, payload)
	case proto.FrameRepair:
		s.handleRepair(hdr, payload)
	case proto.FramePing:
		s.handlePing(hdr, sendReply)
	}
	return 0
}

// handleAuth processes an AuthHello, creates a session, and replies with AuthOK or AuthError.
// Returns the new session ID on success, 0 on failure.
func (s *Server) handleAuth(payload []byte, sendReply func([]byte) error) uint32 {
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

	// The client sends SHA-256(rawPassword) as 32 raw bytes on the wire.
	// We convert to hex — that is the "plain" value stored as bcrypt(sha256hex(password)).
	wireHex := hex.EncodeToString(hello.PWHash[:])
	if err := auth.CheckPassword(wireHex, storedHash); err != nil {
		replyError("invalid credentials")
		return 0
	}

	// Key derivation uses wireHex as token and "hub<ID>" as network name — both sides
	// must agree on these values. The hub's display name is NOT used so the client
	// can derive the same key without knowing it.
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

	sess := &Session{
		ID:       sessionID,
		HubID:    hello.HubID,
		Login:    hello.Login,
		sendRaw:  sendReply,
		cipher:   cipher,
		lastSeen: time.Now(),
	}

	// FEC pipe — sendData and sendRepair encrypt and deliver back to client.
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
			// pipe.Send is mutex-protected internally; no need to hold sess.mu here.
			return sess.pipe.Send(frame)
		},
	}
	h.Join(client)
	log.Printf("auth ok: %s@hub%d session=%d", hello.Login, hello.HubID, sessionID)

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

	// Do NOT hold sess.mu here to avoid deadlock when hub.Forward calls
	// pipe.Send on another session while that session also holds its sess.mu.
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

// sendFECData encrypts one data frame and delivers it to the client via sess.sendRaw.
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
	return sess.sendRaw(append(hdr, encrypted...))
}

// sendFECRepair encrypts one repair symbol and delivers it to the client via sess.sendRaw.
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

// removeSession removes a session from the map and leaves its hub. Used when
// a TCP connection closes before the 90-second cleanup fires.
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
	s.mu.Unlock()
}
