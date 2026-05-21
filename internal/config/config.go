// Package config loads and validates server/client configuration from TOML files.
package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// ServerConfig is the server-side configuration.
type ServerConfig struct {
	Listen       string          `toml:"listen"`        // e.g. "0.0.0.0:5555"
	ListenTCP    string          `toml:"listen_tcp"`    // TCP fallback, e.g. "0.0.0.0:443"
	StatusListen string          `toml:"status_listen"`  // HTTP status API, e.g. "127.0.0.1:9090"
	// UpdateListen is a separate listener for the client update mirror only.
	// Clients download binaries from GET /update/{asset} and check the version
	// via GET /update/version. Typically "0.0.0.0:80" so clients can reach it
	// without a custom port. When empty, /update/* is served on status_listen.
	UpdateListen string          `toml:"update_listen"`
	// UpdateDir is the directory containing client binaries served as a
	// mirror fallback when GitHub is unreachable. The server exposes them at
	// GET /update/{asset} (same base URL as /update/version).
	// Defaults to dist/ next to the server executable when empty.
	UpdateDir    string          `toml:"update_dir"`
	Hubs         []HubConfig     `toml:"hub"`
	FEC          FECConfig       `toml:"fec"`
	TLS          TLSServerConfig `toml:"tls"`
}

// HubConfig defines one hub instance.
type HubConfig struct {
	ID       uint16       `toml:"id"`
	Name     string       `toml:"name"`
	Users    []UserConfig `toml:"user"`
}

// UserConfig is a login+bcrypt_hash pair.
type UserConfig struct {
	Login        string `toml:"login"`
	PasswordHash string `toml:"password_hash"`
}

// ClientConfig is the client-side configuration.
type ClientConfig struct {
	Server       string          `toml:"server"`        // host:port UDP
	ServerTCP    string          `toml:"server_tcp"`    // host:port TCP (fallback or forced)
	StatusListen string          `toml:"status_listen"` // HTTP status API, e.g. "127.0.0.1:9191"
	HubID        uint16          `toml:"hub_id"`
	Login        string          `toml:"login"`
	Password     string          `toml:"password"`
	// Transport selects which protocol to use:
	//   "auto" (default) — try UDP first, fall back to TCP/TLS if server_tcp is set
	//   "udp"            — UDP only, never fall back to TCP
	//   "tcp"            — TCP/TLS only, skip UDP entirely
	Transport string `toml:"transport"`
	// Mode controls adapter selection:
	//   "auto"   (default) — bridge if a 169.254.0.0/16 interface is found, otherwise direct TUN
	//   "direct" — always use direct TUN; skip bridge detection entirely
	//   "bridge" — force bridge mode; fail if no 169.254 interface is found
	Mode string `toml:"mode"`
	// TunName is the WinTun/utun adapter name used in direct mode (no 169.254.x.x interface
	// detected). Defaults to "supervpn".
	TunName string          `toml:"tun_name"`
	FEC     FECConfig       `toml:"fec"`
	TLS     TLSClientConfig `toml:"tls"`
	UDP     UDPConfig       `toml:"udp"`
	Bridge  BridgeConfig    `toml:"bridge"`
	// UpdateMirrors is a list of fallback base URLs tried in order when GitHub
	// is unreachable. Each must serve GET {base}/version → plain-text "bN"
	// and GET {base}/{asset} → binary. Example: supervpn-server status port.
	UpdateMirrors []string `toml:"update_mirrors"`
	// Timeout is expressed as a string (e.g. "30s") and parsed manually to
	// avoid TOML's lack of native time.Duration support.
	Timeout string `toml:"timeout"`
	// MinimizeToTray makes the window hide to the system tray instead of
	// closing or minimizing to the taskbar when the user clicks the close
	// or minimize button.  False by default.
	MinimizeToTray bool `toml:"minimize_to_tray"`
	// AutoConnect, when true, makes the GUI initiate a VPN connection
	// automatically after the saved config is loaded on startup.
	AutoConnect bool `toml:"auto_connect"`
}

// BridgeConfig controls how the client bridges traffic in bridge mode (when a
// 169.254.0.0/16 interface is detected on the local machine).
type BridgeConfig struct {
	// TapName is the name of the tap-windows6 adapter (Windows only).
	// The adapter must be installed and named accordingly.
	// Defaults to "supervpn-tap".
	TapName string `toml:"tap_name"`

	// NIC explicitly names the physical network adapter to bridge
	// (e.g. "Ethernet" or "Local Area Connection").
	// When empty, the client auto-detects a 169.254.0.0/16 interface,
	// skipping virtual adapters (names containing "*").
	NIC string `toml:"nic"`

	// SetupMethod describes how the TAP adapter is bridged to the physical NIC:
	//
	//   "netbridge" (default) — Windows Network Bridge:
	//     The TAP adapter and the physical 169.254 NIC are joined in a Windows
	//     Network Bridge (ncpa.cpl → select both → Bridge Connections, or run
	//     deploy/setup-bridge-netbridge.ps1).  All local devices on the 169.254
	//     subnet reach the hub transparently.
	//
	//   "hyperv" — Hyper-V External Switch:
	//     An External Virtual Switch is created on the physical NIC via
	//     New-VMSwitch (deploy/setup-bridge-hyperv.ps1).  The TAP adapter is
	//     then bridged with the resulting vEthernet adapter.  Requires
	//     Windows Pro/Enterprise with Hyper-V enabled.
	//
	// On Linux and macOS this field is ignored; the native TUN/TAP is used.
	SetupMethod string `toml:"setup_method"`
}

func (b BridgeConfig) WithDefaults() BridgeConfig {
	if b.TapName == "" {
		b.TapName = "supervpn-tap"
	}
	if b.SetupMethod == "" {
		b.SetupMethod = "netbridge"
	}
	return b
}

// UDPConfig controls the knock-and-dial strategy used before each UDP auth attempt.
type UDPConfig struct {
	// KnockCount is the number of random-payload UDP packets sent on the socket
	// before the first auth frame. They prime NAT/firewall state while keeping
	// the 5-tuple identical to the subsequent VPN traffic.
	KnockCount int `toml:"knock_count"` // default 3
	// KnockSize is the payload size of each knock packet in bytes.
	KnockSize int `toml:"knock_size"` // default 16
	// Attempts is how many (knock → auth) cycles to try before falling back to TLS.
	Attempts int `toml:"attempts"` // default 3
}

func (u UDPConfig) WithDefaults() UDPConfig {
	if u.KnockCount == 0 {
		u.KnockCount = 3
	}
	if u.KnockSize == 0 {
		u.KnockSize = 16
	}
	if u.Attempts == 0 {
		u.Attempts = 3
	}
	return u
}

// FECConfig controls redundancy parameters.
type FECConfig struct {
	K           int `toml:"k"`            // data packets per block (default 1)
	R           int `toml:"r"`            // repair packets per block (default 2)
	RepairDelay int `toml:"repair_delay"` // ms to delay repair packets after data (default 50)
}

func (f FECConfig) WithDefaults() FECConfig {
	if f.K == 0 {
		f.K = 1
	}
	if f.R == 0 {
		f.R = 2
	}
	if f.RepairDelay == 0 {
		f.RepairDelay = 50
	}
	return f
}

func (f FECConfig) RepairDelayDuration() time.Duration {
	return time.Duration(f.RepairDelay) * time.Millisecond
}

// Validate returns an error if the config is unusable.
func (s *ServerConfig) Validate() error {
	if s.Listen == "" {
		return fmt.Errorf("config: server.listen is required")
	}
	for _, h := range s.Hubs {
		if h.Name == "" {
			return fmt.Errorf("config: hub id=%d has no name", h.ID)
		}
	}
	return nil
}

func (c *ClientConfig) Validate() error {
	if c.Server == "" {
		return fmt.Errorf("config: client.server is required")
	}
	if c.Login == "" || c.Password == "" {
		return fmt.Errorf("config: login and password are required")
	}
	return nil
}

// LoadServerConfig reads and validates a server config from a TOML file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	var cfg ServerConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	cfg.FEC = cfg.FEC.WithDefaults()
	return &cfg, cfg.Validate()
}

// LoadClientConfig reads and validates a client config from a TOML file.
// Returns an error if parsing fails or if required fields (server, login,
// password) are missing. Use ParseClientConfig in GUI contexts where you
// want to populate widgets from a partial or incomplete config file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg, err := ParseClientConfig(path)
	if err != nil {
		return nil, err
	}
	return cfg, cfg.Validate()
}

// ParseClientConfig reads a client config from a TOML file without validating
// required fields. Use this in GUI contexts where an incomplete config should
// still populate the form fields — validation happens separately when the user
// clicks Connect.
func ParseClientConfig(path string) (*ClientConfig, error) {
	var cfg ClientConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	cfg.FEC = cfg.FEC.WithDefaults()
	cfg.UDP = cfg.UDP.WithDefaults()
	cfg.Bridge = cfg.Bridge.WithDefaults()
	return &cfg, nil
}

// WriteClientConfig encodes cfg as TOML into w.
// Used by GUI save dialogs that write directly to a fyne.URIWriteCloser,
// avoiding the close-and-reopen pattern that causes empty files on macOS.
func WriteClientConfig(w io.Writer, cfg *ClientConfig) error {
	return toml.NewEncoder(w).Encode(cfg)
}

// SaveClientConfig writes cfg to a TOML file at path, creating parent directories as needed.
func SaveClientConfig(path string, cfg *ClientConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("config: mkdir: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("config: create %s: %w", path, err)
	}
	defer f.Close()
	enc := toml.NewEncoder(f)
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	return nil
}

// DefaultServerConfigPath returns the default path to the server config file.
func DefaultServerConfigPath() string {
	if p := os.Getenv("SUPERVPN_CONFIG"); p != "" {
		return p
	}
	return "/etc/supervpn/server.toml"
}

// TLSServerConfig configures the server-side TLS listener.
type TLSServerConfig struct {
	// CertFile and KeyFile are paths to PEM-encoded cert and key.
	// If both are empty, a self-signed ECDSA cert is generated at startup.
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// TLSClientConfig configures the client-side TLS dialer.
type TLSClientConfig struct {
	// SNI is the server name sent in the TLS ClientHello.
	// Set to a popular domain (e.g. "microsoft.com") to mimic HTTPS traffic.
	// Defaults to the server hostname if empty.
	SNI string `toml:"sni"`
	// SkipVerify disables certificate verification (always true for supervpn
	// since the server uses a self-signed cert). Field is informational only.
	SkipVerify bool `toml:"skip_verify"`
}
