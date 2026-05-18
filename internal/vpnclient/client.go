package vpnclient

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/crypto"
	"github.com/atlanteg/supervpn/internal/fec"
	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
)

const (
	pingInterval     = 5 * time.Second
	keepaliveTimeout = 10 * time.Second
	maxLogLines      = 500
)

type State int

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
)

type SessionStats struct {
	State         State
	Transport     string
	Server        string
	HubID         uint16
	Login         string
	SessionID     uint32
	ConnectedAt   time.Time
	SecondaryAddr string
	BytesRx       uint64
	BytesTx       uint64
	FECData       uint64
	FECRepair     uint64
	FECRecovered  uint64
	FECLost       uint64
	LastError     string
	StartTime     time.Time
}

type fecStats struct {
	dataRecv      atomic.Uint64
	repairRecv    atomic.Uint64
	recovered     atomic.Uint64
	unrecoverable atomic.Uint64
	bytesTx       atomic.Uint64
	bytesRx       atomic.Uint64
}

type Client struct {
	Cfg    config.ClientConfig
	Iface  bridge.Interface
	Framer bridge.Framer

	mu        sync.RWMutex
	stats     SessionStats
	sessionFS *fecStats
	logLines  []string
	onChange  func()
	cancelMu  sync.Mutex
	cancel    context.CancelFunc
	running   bool
}

func New(cfg config.ClientConfig, iface bridge.Interface, framer bridge.Framer) *Client {
	return &Client{
		Cfg:    cfg,
		Iface:  iface,
		Framer: framer,
		stats: SessionStats{
			State:     StateDisconnected,
			StartTime: time.Now(),
		},
	}
}

func (c *Client) OnChange(fn func()) {
	c.mu.Lock()
	c.onChange = fn
	c.mu.Unlock()
}

func (c *Client) Stats() SessionStats {
	c.mu.RLock()
	s := c.stats
	fs := c.sessionFS
	c.mu.RUnlock()
	if fs != nil {
		s.BytesTx = fs.bytesTx.Load()
		s.BytesRx = fs.bytesRx.Load()
		s.FECData = fs.dataRecv.Load()
		s.FECRepair = fs.repairRecv.Load()
		s.FECRecovered = fs.recovered.Load()
		s.FECLost = fs.unrecoverable.Load()
	}
	return s
}

func (c *Client) Logs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, len(c.logLines))
	copy(out, c.logLines)
	return out
}

func (c *Client) Logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	c.mu.Lock()
	c.logLines = append(c.logLines, msg)
	if len(c.logLines) > maxLogLines {
		c.logLines = c.logLines[len(c.logLines)-maxLogLines:]
	}
	fn := c.onChange
	c.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (c *Client) IsRunning() bool {
	c.cancelMu.Lock()
	defer c.cancelMu.Unlock()
	return c.running
}

func (c *Client) Start(ctx context.Context) {
	c.cancelMu.Lock()
	if c.running {
		c.cancelMu.Unlock()
		return
	}
	inner, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.running = true
	c.cancelMu.Unlock()
	go c.run(inner)
}

func (c *Client) Stop() {
	c.cancelMu.Lock()
	defer c.cancelMu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	c.running = false
}

func (c *Client) setState(s State) {
	c.mu.Lock()
	c.stats.State = s
	fn := c.onChange
	c.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (c *Client) run(ctx context.Context) {
	defer func() {
		c.cancelMu.Lock()
		c.running = false
		c.cancelMu.Unlock()
		c.setState(StateDisconnected)
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		c.setState(StateConnecting)
		err := c.runSession(ctx)
		if ctx.Err() != nil {
			return
		}
		c.Logf("session ended: %v — reconnecting in 2s", err)
		c.mu.Lock()
		c.stats.State = StateDisconnected
		c.stats.LastError = err.Error()
		c.sessionFS = nil
		fn := c.onChange
		c.mu.Unlock()
		if fn != nil {
			fn()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *Client) runSession(ctx context.Context) error {
	tr, sessionID, sessionCipher, err := c.connectWithFallback(ctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer tr.Close()

	fecCfg := c.Cfg.FEC.WithDefaults()
	udpCfg := c.Cfg.UDP.WithDefaults()

	var tr2 transport.Transport
	if tr.Mode() == "udp" {
		if sec2Addr := deriveSecondaryAddr(c.Cfg.Server); sec2Addr != "" {
			if t2, e := transport.KnockAndDial(sec2Addr, udpCfg.KnockCount, udpCfg.KnockSize); e == nil {
				tr2 = t2
				c.Logf("transport: secondary UDP connected to %s", sec2Addr)
			} else {
				c.Logf("transport: secondary UDP dial %s failed: %v", sec2Addr, e)
			}
		}
	} else {
		tcpAddr := resolveTCPAddr(c.Cfg)
		if sec2Addr := deriveSecondaryAddr(tcpAddr); sec2Addr != "" {
			sni := c.Cfg.TLS.SNI
			if sni == "" {
				if h, _, e := net.SplitHostPort(sec2Addr); e == nil {
					sni = h
				}
			}
			dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
			t2, e := transport.DialTLS(dialCtx, sec2Addr, sni)
			dialCancel()
			if e == nil {
				joinHdr := make([]byte, proto.HeaderSize)
				proto.Header{Type: proto.FrameJoin, SessionID: sessionID}.Marshal(joinHdr)
				if e2 := t2.Send(transport.Frame{Data: joinHdr}); e2 == nil {
					tr2 = t2
					c.Logf("transport: secondary TLS connected to %s", sec2Addr)
				} else {
					t2.Close()
					c.Logf("transport: secondary TLS join %s failed: %v", sec2Addr, e2)
				}
			} else {
				c.Logf("transport: secondary TLS dial %s failed: %v", sec2Addr, e)
			}
		}
	}
	if tr2 != nil {
		defer tr2.Close()
	}

	c.mu.Lock()
	c.stats.State = StateConnected
	c.stats.Transport = tr.Mode()
	c.stats.Server = c.Cfg.Server
	c.stats.HubID = c.Cfg.HubID
	c.stats.Login = c.Cfg.Login
	c.stats.SessionID = sessionID
	c.stats.ConnectedAt = time.Now()
	if tr2 != nil {
		var sec2Addr string
		if tr.Mode() == "udp" {
			sec2Addr = deriveSecondaryAddr(c.Cfg.Server)
		} else {
			sec2Addr = deriveSecondaryAddr(resolveTCPAddr(c.Cfg))
		}
		c.stats.SecondaryAddr = sec2Addr
	} else {
		c.stats.SecondaryAddr = ""
	}
	fn := c.onChange
	c.mu.Unlock()
	if fn != nil {
		fn()
	}

	if tr2 != nil {
		sec2Addr := c.stats.SecondaryAddr
		c.Logf("session %d active via %s+%s fec=K%d/R%d delay=%dms",
			sessionID, tr.Mode(), sec2Addr, fecCfg.K, fecCfg.R, fecCfg.RepairDelay)
	} else {
		c.Logf("session %d active via %s fec=K%d/R%d delay=%dms",
			sessionID, tr.Mode(), fecCfg.K, fecCfg.R, fecCfg.RepairDelay)
	}

	var lastPong atomic.Int64
	lastPong.Store(time.Now().UnixNano())

	var stats fecStats
	c.mu.Lock()
	c.sessionFS = &stats
	c.mu.Unlock()

	pipe, err := fec.NewPipe(
		fecCfg.K,
		fecCfg.R,
		fecCfg.RepairDelayDuration(),
		func(blockID uint32, pktIdx uint16, data []byte) error {
			stats.bytesTx.Add(uint64(len(data)))
			pkt, err := buildFECDataPkt(sessionID, c.Cfg.HubID, sessionCipher, blockID, pktIdx, data)
			if err != nil {
				return err
			}
			sendOnBoth(tr, tr2, pkt)
			return nil
		},
		func(blockID uint32, repairIdx uint8, data []byte) error {
			stats.bytesTx.Add(uint64(len(data)))
			pkt, err := buildFECRepairPkt(sessionID, c.Cfg.HubID, sessionCipher, blockID, repairIdx, uint8(fecCfg.K), uint8(fecCfg.R), data)
			if err != nil {
				return err
			}
			sendOnBoth(tr, tr2, pkt)
			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("fec pipe: %w", err)
	}

	downstream := make(chan []byte, 64)
	b := bridge.New(c.Iface, c.Framer, func(frame []byte) error {
		return pipe.Send(frame)
	})

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	pipe.StartFlush(sessionCtx, 200*time.Millisecond, func(frame []byte) {
		if len(frame) < 14 {
			return
		}
		select {
		case downstream <- frame:
		case <-sessionCtx.Done():
		}
	})

	if tr.Mode() == "tls" && c.Cfg.Transport != "tcp" && c.Cfg.Server != "" {
		go func() {
			t := time.NewTimer(5 * time.Minute)
			defer t.Stop()
			select {
			case <-t.C:
				c.Logf("transport: 5-min TLS session elapsed, probing UDP")
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
		recvErr <- recvLoop(sessionCtx, tr, sessionID, sessionCipher, pipe, fecCfg.K, fecCfg.R, downstream, &lastPong, &stats, c.Logf)
	}()

	if tr2 != nil {
		go func() {
			if err := recvLoop(sessionCtx, tr2, sessionID, sessionCipher, pipe, fecCfg.K, fecCfg.R, downstream, &lastPong, &stats, c.Logf); err != nil {
				c.Logf("secondary recv: %v", err)
			}
		}()
	}

	pingTick := time.NewTicker(pingInterval)
	defer pingTick.Stop()
	var pingSeq uint64
	var prevTx, prevRx uint64

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
			pingSeq++
			sendPing(tr, sessionID, c.Cfg.HubID)
			since := time.Since(time.Unix(0, lastPong.Load()))

			if pingSeq%2 == 0 {
				curTx := stats.bytesTx.Load()
				curRx := stats.bytesRx.Load()
				txKBps := float64(curTx-prevTx) / (2 * pingInterval.Seconds()) / 1024
				rxKBps := float64(curRx-prevRx) / (2 * pingInterval.Seconds()) / 1024
				prevTx, prevRx = curTx, curRx
				c.Logf("keepalive: ping #%d sent, last pong %s ago | FEC data=%d repair=%d recovered=%d lost=%d | ↑%.1f KB/s ↓%.1f KB/s",
					pingSeq, since.Truncate(time.Second),
					stats.dataRecv.Load(), stats.repairRecv.Load(),
					stats.recovered.Load(), stats.unrecoverable.Load(),
					txKBps, rxKBps)
			}
			if since > keepaliveTimeout {
				return fmt.Errorf("keepalive timeout: no pong for %s", since.Truncate(time.Second))
			}
		}
	}
}

func (c *Client) connectWithFallback(ctx context.Context) (transport.Transport, uint32, *crypto.Cipher, error) {
	mode := c.Cfg.Transport
	if mode == "" {
		mode = "auto"
	}

	tcpAddr := resolveTCPAddr(c.Cfg)

	if mode == "tcp" {
		if tcpAddr == "" {
			return nil, 0, nil, fmt.Errorf("transport=tcp but server_tcp is not configured (and cannot be derived from server)")
		}
		return c.connectTLS(ctx, tcpAddr)
	}

	udpCfg := c.Cfg.UDP.WithDefaults()
	for attempt := 1; attempt <= udpCfg.Attempts; attempt++ {
		if ctx.Err() != nil {
			return nil, 0, nil, ctx.Err()
		}
		c.Logf("transport: UDP attempt %d/%d (knock×%d → %s)",
			attempt, udpCfg.Attempts, udpCfg.KnockCount, c.Cfg.Server)

		udpTr, err := transport.KnockAndDial(c.Cfg.Server, udpCfg.KnockCount, udpCfg.KnockSize)
		if err != nil {
			c.Logf("transport: UDP dial: %v", err)
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		sid, cipher, probeErr := authenticate(probeCtx, udpTr, c.Cfg)
		cancel()

		if probeErr == nil {
			c.Logf("transport: UDP connected (attempt %d/%d)", attempt, udpCfg.Attempts)
			return udpTr, sid, cipher, nil
		}
		udpTr.Close()
		c.Logf("transport: UDP attempt %d/%d failed: %v", attempt, udpCfg.Attempts, probeErr)
	}

	if mode == "udp" {
		return nil, 0, nil, fmt.Errorf("UDP unreachable after %d attempts (transport=udp, no TCP fallback)", udpCfg.Attempts)
	}

	if tcpAddr == "" {
		return nil, 0, nil, fmt.Errorf("UDP unreachable after %d attempts and server_tcp is not configured", udpCfg.Attempts)
	}
	return c.connectTLS(ctx, tcpAddr)
}

func (c *Client) connectTLS(ctx context.Context, tcpAddr string) (transport.Transport, uint32, *crypto.Cipher, error) {
	sni := c.Cfg.TLS.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(tcpAddr)
		sni = host
	}
	c.Logf("transport: dialing TLS %s (sni=%s)", tcpAddr, sni)

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	tlsTr, err := transport.DialTLS(dialCtx, tcpAddr, sni)
	dialCancel()
	if err != nil {
		c.Logf("transport: TLS dial %s failed: %v", tcpAddr, err)
		return nil, 0, nil, fmt.Errorf("TLS dial: %w", err)
	}
	c.Logf("transport: TLS handshake ok, authenticating")

	authCtx, authCancel := context.WithTimeout(ctx, 10*time.Second)
	sid, cipher, err := authenticate(authCtx, tlsTr, c.Cfg)
	authCancel()
	if err != nil {
		tlsTr.Close()
		c.Logf("transport: TLS auth failed: %v", err)
		return nil, 0, nil, fmt.Errorf("TLS auth: %w", err)
	}

	c.Logf("transport: TLS connected via %s session=%d", tcpAddr, sid)
	return tlsTr, sid, cipher, nil
}

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

func ServerHost(addr string) string {
	i := len(addr) - 1
	for i >= 0 && addr[i] != ':' {
		i--
	}
	if i <= 0 {
		return addr
	}
	return addr[:i]
}

func recvLoop(ctx context.Context, tr transport.Transport, sessionID uint32, cipher *crypto.Cipher, pipe *fec.Pipe, localK, localR int, out chan<- []byte, lastPong *atomic.Int64, stats *fecStats, logf func(string, ...interface{})) error {
	var replay crypto.ReplayWindow
	var fecMismatchLogged bool
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
			stats.dataRecv.Add(1)
			stats.bytesRx.Add(uint64(len(frame)))
			blockID, pktIdx := proto.UnpackDataSeq(hdr.Seq)
			delivered, err := pipe.RecvData(blockID, pktIdx, frame)
			if err != nil {
				stats.unrecoverable.Add(1)
				continue
			}
			for _, rf := range delivered {
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
			stats.repairRecv.Add(1)
			stats.bytesRx.Add(uint64(len(frame)))
			blockID, repairIdx, blockK, blockR := proto.UnpackRepairSeq(hdr.Seq)
			if !fecMismatchLogged && (int(blockK) != localK || int(blockR) != localR) {
				logf("FEC MISMATCH: server K=%d/R=%d, client K=%d/R=%d — fix fec.k and fec.r in config to match the server",
					blockK, blockR, localK, localR)
				fecMismatchLogged = true
				return fmt.Errorf("FEC mismatch: server K=%d/R=%d vs client K=%d/R=%d", blockK, blockR, localK, localR)
			}
			delivered, err := pipe.RecvRepair(blockID, repairIdx, blockK, blockR, frame)
			if err != nil {
				stats.unrecoverable.Add(1)
				continue
			}
			if len(delivered) > 0 {
				stats.recovered.Add(uint64(len(delivered)))
				for _, rf := range delivered {
					if len(rf) < 14 {
						continue
					}
					select {
					case out <- rf:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}

		case proto.FramePong:
			lastPong.Store(time.Now().UnixNano())
			logf("keepalive: pong received from server")
		}
	}
}

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

func buildFECDataPkt(sessionID uint32, hubID uint16, cipher *crypto.Cipher, blockID uint32, pktIdx uint16, frame []byte) ([]byte, error) {
	encrypted, err := cipher.Seal(frame)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{
		Type:      proto.FrameData,
		HubID:     hubID,
		SessionID: sessionID,
		Seq:       proto.PackDataSeq(blockID, pktIdx),
	}.Marshal(hdr)
	return append(hdr, encrypted...), nil
}

func buildFECRepairPkt(sessionID uint32, hubID uint16, cipher *crypto.Cipher, blockID uint32, repairIdx, blockK, blockR uint8, data []byte) ([]byte, error) {
	encrypted, err := cipher.Seal(data)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{
		Type:      proto.FrameRepair,
		HubID:     hubID,
		SessionID: sessionID,
		Seq:       proto.PackRepairSeq(blockID, repairIdx, blockK, blockR),
	}.Marshal(hdr)
	return append(hdr, encrypted...), nil
}

func sendOnBoth(tr1, tr2 transport.Transport, pkt []byte) {
	_ = tr1.Send(transport.Frame{Data: pkt})
	if tr2 != nil {
		_ = tr2.Send(transport.Frame{Data: pkt})
	}
}

func sendPing(tr transport.Transport, sessionID uint32, hubID uint16) {
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FramePing, HubID: hubID, SessionID: sessionID}.Marshal(hdr)
	_ = tr.Send(transport.Frame{Data: hdr})
}
