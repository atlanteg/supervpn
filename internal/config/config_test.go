package config

import "testing"

func TestMigrateClientConfig(t *testing.T) {
	cases := []struct {
		name        string
		serverTCP   string
		realityAddr string
		wantTCP     string
		wantReality string
		wantChanged bool
	}{
		{"old TLS port", "vpn.example.com:443", "", "vpn.example.com:8443", "", true},
		{"old reality port", "", "vpn.example.com:8443", "", "vpn.example.com:443", true},
		{"both stale", "host:443", "host:8443", "host:8443", "host:443", true},
		{"already current", "host:8443", "host:443", "host:8443", "host:443", false},
		{"empty", "", "", "", "", false},
		{"unrelated port", "host:5555", "host:9000", "host:5555", "host:9000", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &ClientConfig{ServerTCP: c.serverTCP}
			cfg.Reality.Addr = c.realityAddr
			changed := MigrateClientConfig(cfg)
			if changed != c.wantChanged {
				t.Errorf("changed = %v, want %v", changed, c.wantChanged)
			}
			if cfg.ServerTCP != c.wantTCP {
				t.Errorf("ServerTCP = %q, want %q", cfg.ServerTCP, c.wantTCP)
			}
			if cfg.Reality.Addr != c.wantReality {
				t.Errorf("Reality.Addr = %q, want %q", cfg.Reality.Addr, c.wantReality)
			}
		})
	}
}
