// supervpn-client — L2 VPN client with transparent 169.254.0.0/16 bridge.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atlanteg/supervpn/internal/clientadapter"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/update"
	"github.com/atlanteg/supervpn/internal/vpnclient"
	"github.com/atlanteg/supervpn/internal/zgw"
)

var version = "dev"

var globalClient *vpnclient.Client

func main() {
	update.CleanupOldFiles()
	killStaleClient()
	if err := os.WriteFile(pidFilePath(), []byte(strconv.Itoa(os.Getpid())), 0644); err == nil {
		defer os.Remove(pidFilePath())
	}

	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to client config file (optional)")

	var (
		serverFlag        = flag.String("server", "", "server UDP address host:port")
		serverTCPFlag     = flag.String("server-tcp", "", "server TCP/TLS address host:port")
		hubIDFlag         = flag.Uint("hub", 0, "hub ID (default 1)")
		loginFlag         = flag.String("login", "", "login")
		passwordFlag      = flag.String("password", "", "password")
		transportFlag     = flag.String("transport", "", "transport: auto|udp|tcp")
		modeFlag          = flag.String("mode", "", "adapter mode: auto|direct|bridge")
		tunNameFlag       = flag.String("tun-name", "", "TUN/TAP adapter name (direct mode)")
		statusListenFlag  = flag.String("status-listen", "", "HTTP status API listen addr (e.g. 127.0.0.1:9191)")
		timeoutFlag       = flag.String("timeout", "", "session timeout (e.g. 30s)")
		updateMirrorsFlag = flag.String("update-mirrors", "", "comma-separated update mirror URLs")
		fecKFlag          = flag.Int("fec-k", -1, "FEC data packets per block")
		fecRFlag          = flag.Int("fec-r", -1, "FEC repair packets per block")
		fecDelayFlag      = flag.Int("fec-delay", -1, "FEC repair delay ms")
		tlsSNIFlag        = flag.String("tls-sni", "", "TLS SNI hostname")
		udpKnockCountFlag = flag.Int("udp-knock-count", -1, "UDP knock packet count")
		udpKnockSizeFlag  = flag.Int("udp-knock-size", -1, "UDP knock packet size bytes")
		udpAttemptsFlag   = flag.Int("udp-attempts", -1, "UDP auth attempt count before TCP fallback")
		bridgeNICFlag     = flag.String("bridge-nic", "", "physical NIC name to bridge")
		bridgeTAPFlag     = flag.String("bridge-tap", "", "TAP adapter name (Windows bridge mode)")
		bridgeMethodFlag  = flag.String("bridge-method", "", "bridge setup method: netbridge|hyperv")
	)
	flag.Parse()

	var cfg config.ClientConfig
	if cfgPath != "" {
		loaded, err := config.LoadClientConfig(cfgPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		cfg = *loaded
	}

	if *serverFlag != "" {
		cfg.Server = *serverFlag
	}
	if *serverTCPFlag != "" {
		cfg.ServerTCP = *serverTCPFlag
	}
	if *hubIDFlag != 0 {
		cfg.HubID = uint16(*hubIDFlag)
	}
	if cfg.HubID == 0 {
		cfg.HubID = 1
	}
	if *loginFlag != "" {
		cfg.Login = *loginFlag
	}
	if *passwordFlag != "" {
		cfg.Password = *passwordFlag
	}
	if *transportFlag != "" {
		cfg.Transport = *transportFlag
	}
	if *modeFlag != "" {
		cfg.Mode = *modeFlag
	}
	if *tunNameFlag != "" {
		cfg.TunName = *tunNameFlag
	}
	if *statusListenFlag != "" {
		cfg.StatusListen = *statusListenFlag
	}
	if *timeoutFlag != "" {
		cfg.Timeout = *timeoutFlag
	}
	if *updateMirrorsFlag != "" {
		for _, u := range strings.Split(*updateMirrorsFlag, ",") {
			if u = strings.TrimSpace(u); u != "" {
				cfg.UpdateMirrors = append(cfg.UpdateMirrors, u)
			}
		}
	}
	if *fecKFlag >= 0 {
		cfg.FEC.K = *fecKFlag
	}
	if *fecRFlag >= 0 {
		cfg.FEC.R = *fecRFlag
	}
	if *fecDelayFlag >= 0 {
		cfg.FEC.RepairDelay = *fecDelayFlag
	}
	if *tlsSNIFlag != "" {
		cfg.TLS.SNI = *tlsSNIFlag
	}
	if *udpKnockCountFlag >= 0 {
		cfg.UDP.KnockCount = *udpKnockCountFlag
	}
	if *udpKnockSizeFlag >= 0 {
		cfg.UDP.KnockSize = *udpKnockSizeFlag
	}
	if *udpAttemptsFlag >= 0 {
		cfg.UDP.Attempts = *udpAttemptsFlag
	}
	if *bridgeNICFlag != "" {
		cfg.Bridge.NIC = *bridgeNICFlag
	}
	if *bridgeTAPFlag != "" {
		cfg.Bridge.TapName = *bridgeTAPFlag
	}
	if *bridgeMethodFlag != "" {
		cfg.Bridge.SetupMethod = *bridgeMethodFlag
	}
	cfg.FEC = cfg.FEC.WithDefaults()
	cfg.UDP = cfg.UDP.WithDefaults()
	cfg.Bridge = cfg.Bridge.WithDefaults()

	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Merge: explicit/config mirrors first, then all known server mirrors as fallback.
	mirrors := append(cfg.UpdateMirrors, update.DefaultMirrors()...)
	update.CheckAndUpdate(version, update.AssetForClient(), mirrors)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// BMW ZGW discovery — log each state change.
	go zgw.Run(ctx, func(info *zgw.Info) {
		if info != nil {
			log.Printf("BMW found: %s", info)
		} else {
			log.Printf("BMW: not found")
		}
	})

	if cfg.StatusListen != "" {
		go runClientStatusServer(ctx, cfg.StatusListen)
	}

	iface, framer, adapterMode, err := clientadapter.OpenAdapter(cfg)
	if err != nil {
		log.Fatalf("tun: %v", err)
	}
	defer framer.Close()

	log.Printf("supervpn-client %s: server=%s hub=%d login=%s mode=%s",
		version, cfg.Server, cfg.HubID, cfg.Login, adapterMode)

	client := vpnclient.New(cfg, iface, framer, adapterMode)
	globalClient = client
	client.Start(ctx)

	<-ctx.Done()
	client.Stop()
}

func pidFilePath() string {
	return filepath.Join(os.TempDir(), "supervpn-client.pid")
}

func killStaleClient() {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 || pid == os.Getpid() {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	if err := proc.Kill(); err == nil {
		log.Printf("killed stale supervpn-client process (pid=%d)", pid)
		time.Sleep(200 * time.Millisecond)
	}
}

type clientStatusResponse struct {
	Version string          `json:"version"`
	Uptime  string          `json:"uptime"`
	State   string          `json:"state"`
	Session *sessionDetails `json:"session,omitempty"`
}

type sessionDetails struct {
	SessionID     uint32 `json:"session_id"`
	Server        string `json:"server"`
	HubID         uint16 `json:"hub_id"`
	Login         string `json:"login"`
	Mode          string `json:"mode"`
	SecondaryAddr string `json:"secondary_addr,omitempty"`
	ConnectedAt   string `json:"connected_at"`
	Duration      string `json:"duration"`
	FECDataRx     uint64 `json:"fec_data_rx"`
	FECRepairRx   uint64 `json:"fec_repair_rx"`
	FECRecovered  uint64 `json:"fec_recovered"`
	FECLost       uint64 `json:"fec_lost"`
	BytesTx       uint64 `json:"bytes_tx"`
	BytesRx       uint64 `json:"bytes_rx"`
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

	var resp clientStatusResponse
	resp.Version = version

	c := globalClient
	if c == nil {
		resp.State = "starting"
		resp.Uptime = "0s"
		writeJSON(w, resp)
		return
	}

	stats := c.Stats()
	resp.Uptime = now.Sub(stats.StartTime).Truncate(time.Second).String()

	switch stats.State {
	case vpnclient.StateConnected:
		resp.State = "connected"
	case vpnclient.StateConnecting:
		resp.State = "connecting"
	default:
		resp.State = "reconnecting"
	}

	if stats.State == vpnclient.StateConnected {
		sd := &sessionDetails{
			SessionID:     stats.SessionID,
			Server:        stats.Server,
			HubID:         stats.HubID,
			Login:         stats.Login,
			Mode:          stats.Transport,
			SecondaryAddr: stats.SecondaryAddr,
			ConnectedAt:   stats.ConnectedAt.UTC().Format(time.RFC3339),
			Duration:      now.Sub(stats.ConnectedAt).Truncate(time.Second).String(),
			FECDataRx:     stats.FECData,
			FECRepairRx:   stats.FECRepair,
			FECRecovered:  stats.FECRecovered,
			FECLost:       stats.FECLost,
			BytesTx:       stats.BytesTx,
			BytesRx:       stats.BytesRx,
		}
		resp.Session = sd
	}

	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
