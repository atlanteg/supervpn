// Package config loads and validates server/client configuration from TOML files.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// ServerConfig is the server-side configuration.
type ServerConfig struct {
	Listen     string          `toml:"listen"`      // e.g. "0.0.0.0:5555"
	ListenTCP  string          `toml:"listen_tcp"`  // TCP fallback, e.g. "0.0.0.0:443"
	Hubs       []HubConfig     `toml:"hub"`
	FEC        FECConfig       `toml:"fec"`
	TLS        TLSServerConfig `toml:"tls"`
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
	Server    string          `toml:"server"`     // host:port UDP
	ServerTCP string          `toml:"server_tcp"` // host:port TCP fallback
	HubID     uint16          `toml:"hub_id"`
	Login     string          `toml:"login"`
	Password  string          `toml:"password"`
	FEC       FECConfig       `toml:"fec"`
	TLS       TLSClientConfig `toml:"tls"`
	// Timeout is expressed as a string (e.g. "30s") and parsed manually to
	// avoid TOML's lack of native time.Duration support.
	Timeout string `toml:"timeout"`
}

// FECConfig controls redundancy parameters.
type FECConfig struct {
	K int `toml:"k"` // data packets per block (default 20)
	R int `toml:"r"` // repair packets per block (default 1)
}

func (f FECConfig) WithDefaults() FECConfig {
	if f.K == 0 {
		f.K = 20
	}
	if f.R == 0 {
		f.R = 6
	}
	return f
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
func LoadClientConfig(path string) (*ClientConfig, error) {
	var cfg ClientConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	cfg.FEC = cfg.FEC.WithDefaults()
	return &cfg, cfg.Validate()
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
