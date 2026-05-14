// supervpn-server — L2 VPN server with multi-hub support.
// Listens on UDP (primary) and TCP (fallback) for client connections.
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
	"github.com/atlanteg/supervpn/internal/hub"
	"github.com/atlanteg/supervpn/internal/proto"
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
	ID           uint32
	HubID        uint16
	Login        string
	Addr         *net.UDPAddr
	cipher       *crypto.Cipher
	replay       crypto.ReplayWindow // per-session replay window; must not be copied after first use
	lastSeen     time.Time
	mu           sync.Mutex
}

// Server is the UDP server that handles auth, data forwarding, and ping/pong.
type Server struct {
	cfg      *config.ServerConfig
	manager  *hub.Manager
	conn     *net.UDPConn
	sessions map[uint32]*Session
	mu       sync.RWMutex
}

// Run starts the UDP listener and blocks until ctx is cancelled or a fatal error occurs.
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
			// If we get here after ctx cancellation the conn is closed; return gracefully.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handlePacket(pkt, raddr)
	}
}

func (s *Server) handlePacket(pkt []byte, raddr *net.UDPAddr) {
	hdr, ok := proto.ParseHeader(pkt)
	if !ok {
		return
	}
	payload := pkt[proto.HeaderSize:]
	switch hdr.Type {
	case proto.FrameAuth:
		s.handleAuth(payload, raddr)
	case proto.FrameData:
		s.handleData(hdr, payload, raddr)
	case proto.FramePing:
		s.handlePing(hdr, raddr)
	}
}

func (s *Server) handleAuth(payload []byte, raddr *net.UDPAddr) {
	if len(payload) == 0 {
		return
	}
	if payload[0] != proto.AuthMsgHello {
		return
	}
	hello, err := proto.ParseAuthHello(payload[1:])
	if err != nil {
		s.sendAuthError(raddr, 0, "malformed auth request")
		return
	}
	h, ok := s.manager.Get(hello.HubID)
	if !ok {
		s.sendAuthError(raddr, 0, "hub not found")
		return
	}

	// Find user in config.
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
		s.sendAuthError(raddr, 0, "invalid credentials")
		return
	}

	// The client sends SHA-256(rawPassword) as 32 raw bytes.
	// Convert to hex string — that is the "plain" value we stored as bcrypt(sha256hex(password)).
	wireHex := hex.EncodeToString(hello.PWHash[:])
	if err := auth.CheckPassword(wireHex, storedHash); err != nil {
		s.sendAuthError(raddr, 0, "invalid credentials")
		return
	}

	// Create session.
	sessionID := s.newSessionID()
	key, err := crypto.DeriveKey(storedHash, h.Name(), "server", hello.Login)
	if err != nil {
		s.sendAuthError(raddr, 0, "internal error")
		return
	}
	cipher, err := crypto.NewCipher(key, sessionID)
	if err != nil {
		s.sendAuthError(raddr, 0, "internal error")
		return
	}
	sess := &Session{
		ID:       sessionID,
		HubID:    hello.HubID,
		Login:    hello.Login,
		Addr:     raddr,
		cipher:   cipher,
		lastSeen: time.Now(),
	}
	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.mu.Unlock()

	client := &hub.Client{
		SessionID: sessionID,
		Login:     hello.Login,
		Send:      func(frame []byte) error { return s.sendFrame(sess, frame) },
	}
	h.Join(client)
	log.Printf("auth ok: %s@hub%d session=%d from=%s", hello.Login, hello.HubID, sessionID, raddr)
	s.sendAuthOK(raddr, sessionID)
}

func (s *Server) handleData(hdr proto.Header, payload []byte, raddr *net.UDPAddr) {
	s.mu.RLock()
	sess, ok := s.sessions[hdr.SessionID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	sess.lastSeen = time.Now()
	sess.mu.Unlock()

	// Use the per-session replay window (stored in the Session struct).
	frame, err := sess.cipher.Open(payload, &sess.replay)
	if err != nil {
		return
	}
	h, ok := s.manager.Get(sess.HubID)
	if !ok {
		return
	}
	h.Forward(hdr.SessionID, frame)
}

func (s *Server) handlePing(hdr proto.Header, raddr *net.UDPAddr) {
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
	s.conn.WriteToUDP(pong, raddr)
}

func (s *Server) sendFrame(sess *Session, frame []byte) error {
	encrypted, err := sess.cipher.Seal(frame)
	if err != nil {
		return err
	}
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{
		Type:      proto.FrameData,
		HubID:     sess.HubID,
		SessionID: sess.ID,
	}.Marshal(hdr)
	pkt := append(hdr, encrypted...)
	_, err = s.conn.WriteToUDP(pkt, sess.Addr)
	return err
}

func (s *Server) sendAuthOK(raddr *net.UDPAddr, sessionID uint32) {
	ok := proto.AuthOK{SessionID: sessionID}
	payload := append([]byte{proto.AuthMsgOK}, ok.Marshal()...)
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameAuth}.Marshal(hdr)
	s.conn.WriteToUDP(append(hdr, payload...), raddr)
}

func (s *Server) sendAuthError(raddr *net.UDPAddr, sessionID uint32, msg string) {
	ae := proto.AuthError{Message: msg}
	payload := append([]byte{proto.AuthMsgError}, ae.Marshal()...)
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameAuth, SessionID: sessionID}.Marshal(hdr)
	s.conn.WriteToUDP(append(hdr, payload...), raddr)
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
