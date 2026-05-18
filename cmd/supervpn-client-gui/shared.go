package main

// version is set at build time via -ldflags "-X main.version=bN".
var version = "dev"

// predefinedServers is the built-in server list shown in the dropdown on all platforms.
var predefinedServers = []struct{ name, addr string }{
	{"RDVM", "185.108.16.16:5555"},
	{"ADVM", "212.48.224.5:5555"},
	{"RAVM", "81.27.241.25:5555"},
	{"HE2", "49.13.4.85:5555"},
	{"HE3", "162.55.48.218:5555"},
}
