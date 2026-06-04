// Package config loads and validates server/client configuration from TOML files.
package config

import (
	"fmt"
	"io"
	"log"
	"net"
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
	Reality      RealityServerConfig `toml:"reality"`
}

// Default camouflage server names. Reality and plain TLS use DIFFERENT, real,
// high-traffic TLS-1.3 hosts from unrelated providers so the two paths don't
// share a fingerprint and each blends into ordinary HTTPS.
//
//   DefaultRealitySNI — also the Reality dest the server proxies probes to, so
//     it MUST be a genuinely reachable TLS-1.3 host. www.gstatic.com is Google's
//     static CDN: ubiquitous, no redirects, an excellent Reality front.
//   DefaultTLSSNI — wire-only camouflage for the plain-TLS ClientHello (the
//     server's TLS listener ignores SNI / uses a self-signed cert), so it need
//     not be reachable by the server. cdnjs.cloudflare.com is a different
//     provider (Cloudflare) loaded by a huge share of websites.
//
// Override per side if needed, keeping the Reality client SNI coherent with the
// server dest/server_names.
const (
	DefaultRealitySNI = "www.gstatic.com"
	DefaultTLSSNI     = "cdnjs.cloudflare.com"
)

// RealityServerConfig configures the Reality (VLESS+Reality-style) listener.
// When Listen is empty the listener is disabled.
type RealityServerConfig struct {
	// Listen is the TCP address for the Reality listener, e.g. "0.0.0.0:8443".
	// Point port 443 at it to blend in with HTTPS.
	Listen string `toml:"listen"`
	// Dest is the real site probers are transparently proxied to, given as
	// host:port, e.g. "www.microsoft.com:443". It should match the SNI clients
	// send so active probes see a coherent, genuine TLS endpoint.
	Dest string `toml:"dest"`
	// ServerNames, when non-empty, is the allowlist of SNIs an authorized client
	// may send (keep coherent with Dest, e.g. ["www.microsoft.com"]). A client
	// using any other SNI is treated as a prober and proxied to Dest. Empty =
	// accept any SNI.
	ServerNames []string `toml:"server_names"`
	// PrivateKey is the base64 X25519 private key (generate with reality-keygen).
	PrivateKey string `toml:"private_key"`
	// PrivateKeys is the private-key pool matching the public keys embedded in
	// clients (generate with `supervpn-server reality-genpool`). Deploy this to
	// every server; clients pick a public key at random per connection. When set,
	// it is combined with PrivateKey. Keep this OUT of any public repo/binary.
	PrivateKeys []string `toml:"private_keys"`
	// ShortIDs is the set of accepted shortID identifiers (≤8 bytes each).
	// Empty means accept a single all-zero shortID.
	ShortIDs []string `toml:"short_ids"`
	// TimeWindow is the ± tolerance in seconds for the timestamp embedded in
	// the client auth blob (default 90).
	TimeWindow int `toml:"time_window"`
	// Disable turns the Reality listener off. It is enabled by default (a
	// zero-config server runs Reality on :443 with the built-in key pool).
	Disable bool `toml:"disable"`
}

// WithDefaults fills zero-config-friendly defaults so the Reality listener
// works out of the box on :443 with the built-in key pool. Reality is the
// stealth front on the standard HTTPS port; plain TLS lives on :8443.
func (r RealityServerConfig) WithDefaults() RealityServerConfig {
	if r.Listen == "" {
		r.Listen = "0.0.0.0:443"
	}
	if r.Dest == "" {
		r.Dest = DefaultRealitySNI + ":443"
	}
	if len(r.ServerNames) == 0 {
		r.ServerNames = []string{DefaultRealitySNI}
	}
	if r.TimeWindow == 0 {
		r.TimeWindow = 90
	}
	return r
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
	//   "reality"        — Reality (VLESS+Reality-style) only; uses [reality]
	Transport string `toml:"transport"`
	// Mode controls adapter selection:
	//   "auto"   (default) — bridge if a 169.254.0.0/16 interface is found, otherwise direct TUN
	//   "direct" — always use direct TUN; skip bridge detection entirely
	//   "bridge" — force bridge mode; fail if no 169.254 interface is found
	Mode string `toml:"mode"`
	// TunName is the WinTun/utun adapter name used in direct mode (no 169.254.x.x interface
	// detected). Defaults to "supervpn".
	TunName string          `toml:"tun_name"`
	FEC     FECConfig           `toml:"fec"`
	TLS     TLSClientConfig     `toml:"tls"`
	UDP     UDPConfig           `toml:"udp"`
	Bridge  BridgeConfig        `toml:"bridge"`
	Reality RealityClientConfig `toml:"reality"`
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
	// StartWithWindows, when true, registers a Windows Scheduled Task so the
	// client launches automatically at user logon with elevated privileges.
	// Has no effect on non-Windows platforms.
	StartWithWindows bool `toml:"start_with_windows"`
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
	cfg.Reality = cfg.Reality.WithDefaults()
	// Port layout: Reality (stealth VLESS+Reality) on the standard HTTPS :443,
	// plain TLS/TCP on :8443. Defaulting listen_tcp keeps the plain fallback
	// available out of the box without colliding with Reality on :443.
	if cfg.ListenTCP == "" {
		cfg.ListenTCP = "0.0.0.0:8443"
	}
	// Reality owns :443 by design. If plain TLS was left on the same port
	// (e.g. an old config with listen_tcp = ":443"), move it to :8443 so the
	// two listeners don't fight over the port — otherwise one fails to bind.
	if !cfg.Reality.Disable && samePort(cfg.ListenTCP, cfg.Reality.Listen) {
		cfg.ListenTCP = "0.0.0.0:8443"
	}
	return &cfg, cfg.Validate()
}

// samePort reports whether two host:port addresses share the same port.
func samePort(a, b string) bool {
	_, pa, ea := net.SplitHostPort(a)
	_, pb, eb := net.SplitHostPort(b)
	return ea == nil && eb == nil && pa == pb
}

// MigrateClientConfig rewrites settings saved under older port conventions to
// the current layout — Reality on the standard HTTPS :443, plain TLS/TCP on
// :8443 — so a stale config keeps working without manual editing. Returns true
// if anything changed.
//
// Older configs commonly have server_tcp = "host:443" (TLS used to live on 443
// before Reality took it) or reality.addr = "host:8443" (Reality's first
// suggested port). Both are corrected here.
func MigrateClientConfig(cfg *ClientConfig) bool {
	changed := false
	if newAddr, ok := remapPort(cfg.ServerTCP, "443", "8443"); ok {
		cfg.ServerTCP = newAddr
		changed = true
	}
	if newAddr, ok := remapPort(cfg.Reality.Addr, "8443", "443"); ok {
		cfg.Reality.Addr = newAddr
		changed = true
	}
	if changed {
		log.Printf("config: migrated stale ports to current layout (plain TLS→8443, Reality→443)")
	}
	return changed
}

// remapPort returns addr with its port changed from oldPort to newPort, and ok
// = true if a remap happened. Leaves addr untouched (ok=false) when it is empty,
// unparseable, or on a different port.
func remapPort(addr, oldPort, newPort string) (string, bool) {
	if addr == "" {
		return addr, false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != oldPort {
		return addr, false
	}
	return net.JoinHostPort(host, newPort), true
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
	cfg.Reality = cfg.Reality.WithDefaults()
	MigrateClientConfig(&cfg)
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

// RealityClientConfig configures the client-side Reality dialer.
type RealityClientConfig struct {
	// Addr is the Reality server host:port. When empty, the client falls back
	// to the top-level `server` host with port 8443.
	Addr string `toml:"addr"`
	// SNI is the fronting server name sent in the ClientHello, e.g.
	// "www.microsoft.com". It should match the server's dest site.
	SNI string `toml:"sni"`
	// PublicKey is the base64 X25519 server Reality public key.
	PublicKey string `toml:"public_key"`
	// ShortID is this client's shortID identifier (≤8 bytes); must be in the
	// server's short_ids list.
	ShortID string `toml:"short_id"`
	// Fingerprint selects the browser ClientHello to mimic:
	// "chrome" (default), "firefox", "safari", "edge", "ios", "random".
	Fingerprint string `toml:"fingerprint"`
}

func (r RealityClientConfig) WithDefaults() RealityClientConfig {
	if r.Fingerprint == "" {
		r.Fingerprint = "chrome"
	}
	if r.SNI == "" {
		// Coherent with the server's default dest / server_names.
		r.SNI = DefaultRealitySNI
	}
	return r
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
