//go:build windows && !fyne

// Windows GUI built with github.com/lxn/walk (pure Win32/GDI, no OpenGL).
// Works on RDP sessions, Hyper-V VMs, and any environment where GLFW/OpenGL
// is unavailable — which is the case for Fyne on Windows virtual desktops.

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/atlanteg/supervpn/internal/clientadapter"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/vpnclient"
)

type winUI struct {
	form          *walk.MainWindow
	statusBarItem *walk.StatusBarItem

	// Connection tab
	serverPresetCombo *walk.ComboBox
	serverEdit        *walk.LineEdit
	loginEdit         *walk.LineEdit
	passwordEdit      *walk.LineEdit
	hubEdit           *walk.LineEdit
	modeCombo         *walk.ComboBox
	transportCombo    *walk.ComboBox
	configCombo       *walk.ComboBox
	configLabel       *walk.Label
	connectBtn        *walk.PushButton
	disconnectBtn     *walk.PushButton
	statsLabel        *walk.Label

	// Advanced tab
	fecKEdit          *walk.LineEdit
	fecREdit          *walk.LineEdit
	fecDelayEdit      *walk.LineEdit
	tlsSNIEdit        *walk.LineEdit
	knockCountEdit    *walk.LineEdit
	knockSizeEdit     *walk.LineEdit
	udpAttemptsEdit   *walk.LineEdit
	bridgeNICEdit     *walk.LineEdit
	bridgeTAPEdit     *walk.LineEdit
	bridgeMethodCombo *walk.ComboBox
	tunNameEdit       *walk.LineEdit
	statusListenEdit  *walk.LineEdit
	timeoutEdit       *walk.LineEdit

	// Log tab
	logEdit *walk.TextEdit

	// VPN state
	client        *vpnclient.Client
	framer        interface{ Close() error }
	connectCtx    context.Context
	connectCancel context.CancelFunc

	serverPresetNames []string
	serverAddrs       map[string]string // display name → address
	configNames       []string
	configFilePaths   map[string]string // filename → full path
	configPath        string

	refreshCh     chan struct{}
	prevBytesRx   uint64
	prevBytesTx   uint64
	prevStatsTime time.Time
	autoSaveDone  bool
}

func (ui *winUI) runApp() {
	ui.serverAddrs = make(map[string]string)
	ui.configFilePaths = make(map[string]string)
	for _, s := range predefinedServers {
		ui.serverAddrs[s.name] = s.addr
		ui.serverPresetNames = append(ui.serverPresetNames, s.name)
	}

	if err := (MainWindow{
		AssignTo: &ui.form,
		Title:    "superVPN " + version + " by NBTboost creators © Atlanteg",
		MinSize:  Size{Width: 540, Height: 560},
		Size:     Size{Width: 560, Height: 660},
		Layout:   VBox{MarginsZero: true},
		StatusBarItems: []StatusBarItem{
			{AssignTo: &ui.statusBarItem, Text: "Disconnected", Width: -1},
		},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					ui.connectionPage(),
					ui.advancedPage(),
					ui.logPage(),
				},
			},
		},
	}.Create()); err != nil {
		walk.MsgBox(nil, "Error", "Failed to create window: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	ui.initConfigSelect()
	ui.form.Run()
}

func (ui *winUI) connectionPage() TabPage {
	return TabPage{
		Title: "Connection",
		Content: ScrollView{
			Layout: VBox{Spacing: 6},
			Children: []Widget{
				GroupBox{
					Title:  "Server",
					Layout: Grid{Columns: 2, Spacing: 4},
					Children: []Widget{
						Label{Text: "Preset:"},
						ComboBox{
							AssignTo: &ui.serverPresetCombo,
							Model:    ui.serverPresetNames,
							OnCurrentIndexChanged: func() {
								if ui.serverPresetCombo == nil || ui.serverEdit == nil {
									return
								}
								idx := ui.serverPresetCombo.CurrentIndex()
								if idx >= 0 && idx < len(predefinedServers) {
									_ = ui.serverEdit.SetText(predefinedServers[idx].addr)
								}
							},
						},
						Label{Text: "Address:"},
						Composite{
							Layout: HBox{MarginsZero: true, Spacing: 3},
							Children: []Widget{
								LineEdit{
									AssignTo:      &ui.serverEdit,
									StretchFactor: 3,
								},
								PushButton{
									Text:      "Add",
									MaxSize:   Size{Width: 55},
									OnClicked: ui.onAddServer,
								},
							},
						},
						Label{Text: "Login:"},
						LineEdit{AssignTo: &ui.loginEdit},
						Label{Text: "Password:"},
						LineEdit{AssignTo: &ui.passwordEdit, PasswordMode: true},
						Label{Text: "Hub ID:"},
						LineEdit{AssignTo: &ui.hubEdit, Text: "1"},
						Label{Text: "Mode:"},
						ComboBox{
							AssignTo:     &ui.modeCombo,
							Model:        []string{"auto", "direct", "bridge"},
							CurrentIndex: 0,
						},
						Label{Text: "Transport:"},
						ComboBox{
							AssignTo:     &ui.transportCombo,
							Model:        []string{"auto", "udp", "tcp"},
							CurrentIndex: 0,
						},
					},
				},
				GroupBox{
					Title:  "Config file",
					Layout: HBox{Spacing: 4},
					Children: []Widget{
						ComboBox{
							AssignTo:      &ui.configCombo,
							StretchFactor: 3,
							OnCurrentIndexChanged: func() { ui.onConfigSelected() },
						},
						PushButton{Text: "Browse…", MaxSize: Size{Width: 80}, OnClicked: ui.onBrowseConfig},
						PushButton{Text: "Save…", MaxSize: Size{Width: 72}, OnClicked: ui.onSaveConfig},
					},
				},
				Label{AssignTo: &ui.configLabel, Text: ""},
				Composite{
					Layout: HBox{Spacing: 6},
					Children: []Widget{
						PushButton{AssignTo: &ui.connectBtn, Text: "Connect", OnClicked: ui.onConnect},
						PushButton{AssignTo: &ui.disconnectBtn, Text: "Disconnect", Enabled: false, OnClicked: ui.onDisconnect},
					},
				},
				Label{AssignTo: &ui.statsLabel, Text: ""},
				LinkLabel{
					Text: `Packet capture (bridge mode): install <a href="https://npcap.com/dist/npcap-1.88.exe">Npcap 1.88</a>`,
					OnLinkActivated: func(link *walk.LinkLabelLink) {
						exec.Command("rundll32", "url.dll,FileProtocolHandler", link.URL()).Start()
					},
				},
			},
		},
	}
}

func (ui *winUI) advancedPage() TabPage {
	return TabPage{
		Title: "Advanced",
		Content: ScrollView{
			Layout: VBox{Spacing: 6},
			Children: []Widget{
				GroupBox{
					Title:  "FEC",
					Layout: Grid{Columns: 2, Spacing: 4},
					Children: []Widget{
						Label{Text: "K (data packets):"},
						LineEdit{AssignTo: &ui.fecKEdit, Text: "4"},
						Label{Text: "R (repair packets):"},
						LineEdit{AssignTo: &ui.fecREdit, Text: "2"},
						Label{Text: "Repair delay (ms):"},
						LineEdit{AssignTo: &ui.fecDelayEdit, Text: "100"},
					},
				},
				GroupBox{
					Title:  "UDP",
					Layout: Grid{Columns: 2, Spacing: 4},
					Children: []Widget{
						Label{Text: "Knock count:"},
						LineEdit{AssignTo: &ui.knockCountEdit, Text: "3"},
						Label{Text: "Knock size (bytes):"},
						LineEdit{AssignTo: &ui.knockSizeEdit, Text: "16"},
						Label{Text: "Attempts before TCP fallback:"},
						LineEdit{AssignTo: &ui.udpAttemptsEdit, Text: "3"},
					},
				},
				GroupBox{
					Title:  "TLS",
					Layout: Grid{Columns: 2, Spacing: 4},
					Children: []Widget{
						Label{Text: "SNI:"},
						LineEdit{AssignTo: &ui.tlsSNIEdit, Text: ""},
					},
				},
				GroupBox{
					Title:  "Bridge / TUN",
					Layout: Grid{Columns: 2, Spacing: 4},
					Children: []Widget{
						Label{Text: "Bridge NIC:"},
						LineEdit{AssignTo: &ui.bridgeNICEdit},
						Label{Text: "Bridge TAP name:"},
						LineEdit{AssignTo: &ui.bridgeTAPEdit},
						Label{Text: "Bridge method:"},
						ComboBox{
							AssignTo:     &ui.bridgeMethodCombo,
							Model:        []string{"netbridge", "hyperv"},
							CurrentIndex: 0,
						},
						Label{Text: "TUN adapter name:"},
						LineEdit{AssignTo: &ui.tunNameEdit, Text: "supervpn"},
					},
				},
				GroupBox{
					Title:  "Other",
					Layout: Grid{Columns: 2, Spacing: 4},
					Children: []Widget{
						Label{Text: "Status listen:"},
						LineEdit{AssignTo: &ui.statusListenEdit},
						Label{Text: "Session timeout:"},
						LineEdit{AssignTo: &ui.timeoutEdit},
					},
				},
			},
		},
	}
}

func (ui *winUI) logPage() TabPage {
	return TabPage{
		Title: "Log",
		Content: Composite{
			Layout: VBox{MarginsZero: true, Spacing: 3},
			Children: []Widget{
				TextEdit{
					AssignTo:      &ui.logEdit,
					ReadOnly:      true,
					VScroll:       true,
					StretchFactor: 1,
				},
				PushButton{
					Text:      "Clear",
					MaxSize:   Size{Height: 28},
					OnClicked: func() { _ = ui.logEdit.SetText("") },
				},
			},
		},
	}
}

// ── event handlers ────────────────────────────────────────────────────────────

func (ui *winUI) onAddServer() {
	text := strings.TrimSpace(ui.serverEdit.Text())
	if text == "" {
		return
	}
	for i, name := range ui.serverPresetNames {
		if name == text {
			_ = ui.serverPresetCombo.SetCurrentIndex(i)
			return
		}
	}
	ui.serverAddrs[text] = text
	ui.serverPresetNames = append(ui.serverPresetNames, text)
	_ = ui.serverPresetCombo.SetModel(ui.serverPresetNames)
	_ = ui.serverPresetCombo.SetCurrentIndex(len(ui.serverPresetNames) - 1)
}

func (ui *winUI) onConfigSelected() {
	if ui.configCombo == nil {
		return
	}
	idx := ui.configCombo.CurrentIndex()
	if idx < 0 || idx >= len(ui.configNames) {
		return
	}
	path, ok := ui.configFilePaths[ui.configNames[idx]]
	if !ok {
		return
	}
	cfg, err := config.LoadClientConfig(path)
	if err != nil {
		walk.MsgBox(ui.form, "Error", "Cannot load config: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	ui.populateFromConfig(cfg)
	ui.configPath = path
	_ = ui.configLabel.SetText(path)
}

func (ui *winUI) onBrowseConfig() {
	dlg := new(walk.FileDialog)
	dlg.Filter = "TOML Files (*.toml)|*.toml|All Files (*.*)|*.*"
	dlg.Title = "Open Config File"
	ok, err := dlg.ShowOpen(ui.form)
	if err != nil || !ok {
		return
	}
	path := dlg.FilePath
	cfg, err := config.LoadClientConfig(path)
	if err != nil {
		walk.MsgBox(ui.form, "Error", "Cannot load config: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	ui.populateFromConfig(cfg)
	ui.configPath = path
	ui.addConfigToCombo(path)
	_ = ui.configLabel.SetText(path)
}

func (ui *winUI) onSaveConfig() {
	dlg := new(walk.FileDialog)
	dlg.Filter = "TOML Files (*.toml)|*.toml|All Files (*.*)|*.*"
	dlg.Title = "Save Config File"
	ok, err := dlg.ShowSave(ui.form)
	if err != nil || !ok {
		return
	}
	path := dlg.FilePath
	cfg := ui.buildConfig()
	if err := config.SaveClientConfig(path, &cfg); err != nil {
		walk.MsgBox(ui.form, "Error", "Cannot save config: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	ui.configPath = path
	ui.addConfigToCombo(path)
	_ = ui.configLabel.SetText(path)
}

func (ui *winUI) addConfigToCombo(path string) {
	name := filepath.Base(path)
	if _, exists := ui.configFilePaths[name]; !exists {
		ui.configFilePaths[name] = path
		ui.configNames = append(ui.configNames, name)
		_ = ui.configCombo.SetModel(ui.configNames)
	}
	for i, n := range ui.configNames {
		if n == name {
			_ = ui.configCombo.SetCurrentIndex(i)
			break
		}
	}
}

func (ui *winUI) initConfigSelect() {
	var searchDirs []string
	if exe, err := os.Executable(); err == nil {
		searchDirs = append(searchDirs, filepath.Dir(exe))
	}
	if cfgDir, err := os.UserConfigDir(); err == nil {
		searchDirs = append(searchDirs, filepath.Join(cfgDir, "superVPN"))
	}
	if homeDir, err := os.UserHomeDir(); err == nil {
		searchDirs = append(searchDirs, homeDir)
	}

	type entry struct{ displayName, path string }
	var found []entry
	seenPath := map[string]bool{}

	for _, dir := range searchDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.toml"))
		for _, path := range matches {
			if seenPath[path] {
				continue
			}
			seenPath[path] = true
			found = append(found, entry{filepath.Base(path), path})
		}
	}
	if len(found) == 0 {
		return
	}

	baseCount := map[string]int{}
	for _, e := range found {
		baseCount[e.displayName]++
	}
	for i, e := range found {
		if baseCount[e.displayName] > 1 {
			found[i].displayName = filepath.Base(filepath.Dir(e.path)) + "/" + e.displayName
		}
	}

	for _, e := range found {
		ui.configFilePaths[e.displayName] = e.path
		ui.configNames = append(ui.configNames, e.displayName)
	}
	_ = ui.configCombo.SetModel(ui.configNames)
	if len(ui.configNames) == 1 {
		_ = ui.configCombo.SetCurrentIndex(0)
		ui.onConfigSelected()
	}
}

func (ui *winUI) onConnect() {
	cfg := ui.buildConfig()
	ui.connectBtn.SetEnabled(false)
	ui.disconnectBtn.SetEnabled(true)

	go func() {
		iface, framer, adapterMode, err := clientadapter.OpenAdapter(cfg)
		if err != nil {
			ui.form.Synchronize(func() {
				_ = ui.statusBarItem.SetText("Error: " + err.Error())
				ui.connectBtn.SetEnabled(true)
				ui.disconnectBtn.SetEnabled(false)
			})
			return
		}
		ui.framer = framer

		ctx, cancel := context.WithCancel(context.Background())
		ui.connectCtx = ctx
		ui.connectCancel = cancel

		c := vpnclient.New(cfg, iface, framer, adapterMode)
		ui.client = c

		ui.refreshCh = make(chan struct{}, 1)
		c.OnChange(func() {
			select {
			case ui.refreshCh <- struct{}{}:
			default:
			}
		})

		go ui.runRefreshLoop(ctx)
		c.Start(ctx)
	}()
}

func (ui *winUI) onDisconnect() {
	if ui.connectCancel != nil {
		ui.connectCancel()
	}
	if ui.client != nil {
		ui.client.Stop()
		ui.client = nil
	}
	if ui.framer != nil {
		_ = ui.framer.Close()
		ui.framer = nil
	}
	_ = ui.statusBarItem.SetText("Disconnected")
	_ = ui.statsLabel.SetText("")
	ui.prevStatsTime = time.Time{}
	ui.autoSaveDone = false
	ui.connectBtn.SetEnabled(true)
	ui.disconnectBtn.SetEnabled(false)
}

// ── refresh loop ──────────────────────────────────────────────────────────────

// runRefreshLoop drives all periodic UI updates from a single goroutine.
// walk.Synchronize (equivalent of fyne.Do) is used for all widget mutations.
func (ui *winUI) runRefreshLoop(ctx context.Context) {
	logTicker := time.NewTicker(time.Second)
	defer logTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ui.refreshCh:
			ui.doRefreshStatus()
		case <-logTicker.C:
			c := ui.client
			if c == nil {
				return
			}
			// Windows TextEdit uses \r\n line endings.
			text := strings.Join(c.Logs(), "\r\n")
			ui.form.Synchronize(func() { _ = ui.logEdit.SetText(text) })
		}
	}
}

func (ui *winUI) doRefreshStatus() {
	c := ui.client
	if c == nil {
		return
	}
	stats := c.Stats()

	var statusText, statsText string
	switch stats.State {
	case vpnclient.StateConnected:
		statusText = "Connected — " + stats.Transport + " → " + stats.Server
		if stats.AdapterMode != "" {
			statusText += " | " + stats.AdapterMode
		}
	case vpnclient.StateConnecting:
		statusText = "Connecting..."
	default:
		statusText = "Reconnecting..."
		if stats.LastError != "" {
			statusText += " (" + stats.LastError + ")"
		}
	}

	if stats.State == vpnclient.StateConnected {
		now := time.Now()
		var rxSpeed, txSpeed float64
		if !ui.prevStatsTime.IsZero() {
			dt := now.Sub(ui.prevStatsTime).Seconds()
			if dt > 0 {
				rxSpeed = float64(stats.BytesRx-ui.prevBytesRx) / dt / 1024
				txSpeed = float64(stats.BytesTx-ui.prevBytesTx) / dt / 1024
			}
		}
		ui.prevBytesRx = stats.BytesRx
		ui.prevBytesTx = stats.BytesTx
		ui.prevStatsTime = now
		statsText = fmt.Sprintf(
			"↑ %.1f KB/s  ↓ %.1f KB/s  |  Recovered: %d  Lost: %d",
			txSpeed, rxSpeed, stats.FECRecovered, stats.FECLost,
		)
	}

	ui.form.Synchronize(func() {
		_ = ui.statusBarItem.SetText(statusText)
		_ = ui.statsLabel.SetText(statsText)
	})

	if stats.State == vpnclient.StateConnected && !ui.autoSaveDone {
		ui.autoSaveDone = true
		go ui.autoSaveConfig()
	}
}

func (ui *winUI) autoSaveConfig() {
	// Read widget values on the UI thread.
	var cfg config.ClientConfig
	ui.form.Synchronize(func() { cfg = ui.buildConfig() })

	path := ui.configPath
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return
		}
		path = filepath.Join(dir, "superVPN", "client.toml")
	}
	if err := config.SaveClientConfig(path, &cfg); err == nil {
		log.Printf("config auto-saved to %s", path)
		ui.form.Synchronize(func() {
			ui.configPath = path
			_ = ui.configLabel.SetText(path)
			ui.addConfigToCombo(path)
		})
	}
}

// ── config build / populate ───────────────────────────────────────────────────

func (ui *winUI) buildConfig() config.ClientConfig {
	server := strings.TrimSpace(ui.serverEdit.Text())
	if server == "" {
		idx := ui.serverPresetCombo.CurrentIndex()
		if idx >= 0 && idx < len(predefinedServers) {
			server = predefinedServers[idx].addr
		}
	}

	hubID := uint16(1)
	if n, err := strconv.Atoi(ui.hubEdit.Text()); err == nil && n > 0 {
		hubID = uint16(n)
	}
	fecK := 4
	if n, err := strconv.Atoi(ui.fecKEdit.Text()); err == nil && n > 0 {
		fecK = n
	}
	fecR := 2
	if n, err := strconv.Atoi(ui.fecREdit.Text()); err == nil && n >= 0 {
		fecR = n
	}
	fecDelay := 100
	if n, err := strconv.Atoi(ui.fecDelayEdit.Text()); err == nil && n >= 0 {
		fecDelay = n
	}
	knockCount := 3
	if n, err := strconv.Atoi(ui.knockCountEdit.Text()); err == nil && n > 0 {
		knockCount = n
	}
	knockSize := 16
	if n, err := strconv.Atoi(ui.knockSizeEdit.Text()); err == nil && n > 0 {
		knockSize = n
	}
	udpAttempts := 3
	if n, err := strconv.Atoi(ui.udpAttemptsEdit.Text()); err == nil && n > 0 {
		udpAttempts = n
	}

	modeItems := []string{"auto", "direct", "bridge"}
	modeVal := ""
	if idx := ui.modeCombo.CurrentIndex(); idx > 0 && idx < len(modeItems) {
		modeVal = modeItems[idx]
	}

	transportItems := []string{"auto", "udp", "tcp"}
	transportVal := ""
	if idx := ui.transportCombo.CurrentIndex(); idx > 0 && idx < len(transportItems) {
		transportVal = transportItems[idx]
	}

	bridgeMethodItems := []string{"netbridge", "hyperv"}
	bridgeMethod := "netbridge"
	if idx := ui.bridgeMethodCombo.CurrentIndex(); idx >= 0 && idx < len(bridgeMethodItems) {
		bridgeMethod = bridgeMethodItems[idx]
	}

	cfg := config.ClientConfig{
		Server:    server,
		HubID:     hubID,
		Login:     ui.loginEdit.Text(),
		Password:  ui.passwordEdit.Text(),
		Transport: transportVal,
		Mode:      modeVal,
		TunName:   strings.TrimSpace(ui.tunNameEdit.Text()),
		FEC: config.FECConfig{
			K:           fecK,
			R:           fecR,
			RepairDelay: fecDelay,
		},
		TLS: config.TLSClientConfig{
			SNI: strings.TrimSpace(ui.tlsSNIEdit.Text()),
		},
		UDP: config.UDPConfig{
			KnockCount: knockCount,
			KnockSize:  knockSize,
			Attempts:   udpAttempts,
		},
		Bridge: config.BridgeConfig{
			NIC:         strings.TrimSpace(ui.bridgeNICEdit.Text()),
			TapName:     strings.TrimSpace(ui.bridgeTAPEdit.Text()),
			SetupMethod: bridgeMethod,
		},
		StatusListen: strings.TrimSpace(ui.statusListenEdit.Text()),
		Timeout:      strings.TrimSpace(ui.timeoutEdit.Text()),
	}
	cfg.FEC = cfg.FEC.WithDefaults()
	cfg.UDP = cfg.UDP.WithDefaults()
	cfg.Bridge = cfg.Bridge.WithDefaults()
	return cfg
}

func (ui *winUI) populateFromConfig(cfg *config.ClientConfig) {
	_ = ui.serverEdit.SetText(cfg.Server)
	_ = ui.loginEdit.SetText(cfg.Login)
	_ = ui.passwordEdit.SetText(cfg.Password)
	_ = ui.hubEdit.SetText(strconv.Itoa(int(cfg.HubID)))

	modeItems := []string{"auto", "direct", "bridge"}
	mode := cfg.Mode
	if mode == "" {
		mode = "auto"
	}
	for i, m := range modeItems {
		if m == mode {
			_ = ui.modeCombo.SetCurrentIndex(i)
			break
		}
	}

	transportItems := []string{"auto", "udp", "tcp"}
	transport := cfg.Transport
	if transport == "" {
		transport = "auto"
	}
	for i, t := range transportItems {
		if t == transport {
			_ = ui.transportCombo.SetCurrentIndex(i)
			break
		}
	}

	if cfg.FEC.K > 0 {
		_ = ui.fecKEdit.SetText(strconv.Itoa(cfg.FEC.K))
	}
	if cfg.FEC.R > 0 {
		_ = ui.fecREdit.SetText(strconv.Itoa(cfg.FEC.R))
	}
	if cfg.FEC.RepairDelay > 0 {
		_ = ui.fecDelayEdit.SetText(strconv.Itoa(cfg.FEC.RepairDelay))
	}
	_ = ui.tlsSNIEdit.SetText(cfg.TLS.SNI)
	if cfg.UDP.KnockCount > 0 {
		_ = ui.knockCountEdit.SetText(strconv.Itoa(cfg.UDP.KnockCount))
	}
	if cfg.UDP.KnockSize > 0 {
		_ = ui.knockSizeEdit.SetText(strconv.Itoa(cfg.UDP.KnockSize))
	}
	if cfg.UDP.Attempts > 0 {
		_ = ui.udpAttemptsEdit.SetText(strconv.Itoa(cfg.UDP.Attempts))
	}
	_ = ui.bridgeNICEdit.SetText(cfg.Bridge.NIC)
	_ = ui.bridgeTAPEdit.SetText(cfg.Bridge.TapName)
	bridgeMethodItems := []string{"netbridge", "hyperv"}
	for i, m := range bridgeMethodItems {
		if m == cfg.Bridge.SetupMethod {
			_ = ui.bridgeMethodCombo.SetCurrentIndex(i)
			break
		}
	}
	if cfg.TunName != "" {
		_ = ui.tunNameEdit.SetText(cfg.TunName)
	}
	_ = ui.statusListenEdit.SetText(cfg.StatusListen)
	_ = ui.timeoutEdit.SetText(cfg.Timeout)
}
