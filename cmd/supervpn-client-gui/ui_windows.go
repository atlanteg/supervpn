//go:build windows && !fyne

// Windows GUI built with github.com/lxn/walk (pure Win32/GDI, no OpenGL).
// Works on RDP sessions, Hyper-V VMs, and any environment where GLFW/OpenGL
// is unavailable — which is the case for Fyne on Windows virtual desktops.

package main

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"

	"github.com/atlanteg/supervpn/internal/bmwbattery"
	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/clientadapter"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/vpnclient"
	"github.com/atlanteg/supervpn/internal/winfirewall"
	"github.com/atlanteg/supervpn/internal/zgw"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

type winUI struct {
	form          *walk.MainWindow
	statusBarItem *walk.StatusBarItem

	// Connection tab
	serverPresetCombo     *walk.ComboBox
	serverEdit            *walk.LineEdit
	loginEdit             *walk.LineEdit
	passwordEdit          *walk.LineEdit
	hubCombo              *walk.ComboBox
	hubInfos              []proto.HubInfo // last fetched from server; nil = not yet fetched
	modeCombo             *walk.ComboBox
	transportCombo        *walk.ComboBox
	configCombo           *walk.ComboBox
	configLabel           *walk.Label
	connectBtn            *walk.PushButton
	disconnectBtn         *walk.PushButton
	statusDotView         *walk.ImageView // colored circle indicator
	connectionStatusLabel *walk.Label
	statsLabel            *walk.Label

	// Advanced tab
	fecKEdit          *walk.LineEdit
	fecREdit          *walk.LineEdit
	fecDelayEdit      *walk.LineEdit
	tlsSNIEdit        *walk.LineEdit
	knockCountEdit    *walk.LineEdit
	knockSizeEdit     *walk.LineEdit
	udpAttemptsEdit   *walk.LineEdit
	bridgeNICCombo    *walk.ComboBox
	bridgeTAPEdit     *walk.LineEdit
	bridgeMethodCombo *walk.ComboBox
	tunNameEdit       *walk.LineEdit
	tunIPEdit         *walk.LineEdit
	statusListenEdit  *walk.LineEdit
	timeoutEdit       *walk.LineEdit

	// Log tab
	logEdit *walk.TextEdit

	// Npcap install button (connection tab)
	npcapBtn *walk.PushButton

	// BMW ZGW discovery result label (bottom of Connection tab). LinkLabel so
	// the car IP and VIN are clickable — clicking copies them to the clipboard.
	bmwLabel      *walk.LinkLabel
	bmwIP, bmwVIN string

	// Battery data for G-series cars — polled via ENET while the car is live.
	batteryLabel  *walk.Label
	batteryCancel context.CancelFunc
	batteryIP     string // IP of the car currently being polled; "" = not polling

	// Last disconnect time label (bottom of Connection tab)
	disconnectLabel *walk.Label
	lastDisconnect  time.Time
	prevConnected   bool

	// Test tab
	testResultEdit *walk.TextEdit
	testBtn        *walk.PushButton

	// Advanced tab – behavior
	minimizeToTrayCheck   *walk.CheckBox
	autoConnectCheck      *walk.CheckBox
	startWithWindowsCheck *walk.CheckBox
	batteryPollingCheck   *walk.CheckBox

	// System tray icon (created after window init)
	notifyIcon *walk.NotifyIcon

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

	refreshCh      chan struct{}
	prevBytesRx    uint64
	prevBytesTx    uint64
	prevStatsTime  time.Time
	autoSaveDone   bool
	lastLogVersion uint64 // last logVersion rendered to the log tab

	// suppressConfigReload is set to true while addConfigToCombo manipulates
	// the combo programmatically, preventing onConfigSelected from re-loading
	// the config file and overwriting the user's current field values.
	suppressConfigReload bool

	// pendingHubID holds the hub ID from the last loaded config so that
	// fetchAndPopulateHubs can select it after the hub list arrives.
	// Walk's ComboBox.SetText on an empty model does not persist the value.
	pendingHubID uint16
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
					ui.testPage(),
					ui.logPage(),
				},
			},
		},
	}.Create()); err != nil {
		walk.MsgBox(nil, "Error", "Failed to create window: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	ui.centerWindow()
	ui.setupTray()
	ui.setStatusDot(dotGray) // initial disconnected state
	ui.initConfigSelect()
	ui.updateNpcapButton()

	// Disable Windows Firewall for the lifetime of the app — in a goroutine so a
	// slow/hung netsh can never block window creation (the window must always
	// appear). The Closing handler that restores it is registered in setupTray.
	go func() {
		if err := winfirewall.Disable(); err != nil {
			log.Printf("winfirewall disable: %v", err)
		}
	}()

	// Start BMW ZGW discovery — runs independently of VPN connection state.
	// Exclude our own VPN tunnel adapter so it is not mistaken for a BMW ENET cable.
	tunName := strings.TrimSpace(ui.tunNameEdit.Text())
	if tunName == "" {
		tunName = "supervpn"
	}
	go zgw.Run(context.Background(), tunName, func(info *zgw.Info) {
		markup, ip, vin := bmwLinkMarkup(info)
		ui.form.Synchronize(func() {
			ui.bmwIP, ui.bmwVIN = ip, vin
			if ui.bmwLabel != nil {
				_ = ui.bmwLabel.SetText(markup)
			}
			ui.updateBattery(info)
		})
	})

	// Log tab ticker — updates the log tab every 2 s from AppLog regardless of
	// VPN connection state, so ZGW/update/firewall messages are always visible.
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			ver := AppLog.Version()
			if ver == ui.lastLogVersion {
				continue
			}
			ui.lastLogVersion = ver
			logs := AppLog.Lines()
			if len(logs) > maxLogDisplay {
				logs = logs[len(logs)-maxLogDisplay:]
			}
			text := strings.Join(logs, "\r\n")
			ui.form.Synchronize(func() {
				if ui.logEdit != nil {
					_ = ui.logEdit.SetText(text)
				}
			})
		}
	}()

	// 1-second ticker to keep "last disconnect" counter current.
	// Only shown while VPN is Connected; cleared otherwise.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for range t.C {
			var text string
			if ui.prevConnected {
				text = formatAgo(ui.lastDisconnect)
			}
			ui.form.Synchronize(func() {
				if ui.disconnectLabel != nil {
					_ = ui.disconnectLabel.SetText(text)
				}
			})
		}
	}()
	// First-launch Npcap check: if missing, prompt and install the embedded
	// installer on confirmation. Posted via Synchronize so it shows after the
	// window is up; runs before any auto-connect because the MsgBox is modal.
	ui.form.Synchronize(ui.maybeInstallNpcap)

	// Auto-connect: post to the message queue so onConnect runs after the
	// message loop starts (Synchronize uses PostMessage, safe before Run).
	if ui.autoConnectCheck != nil && ui.autoConnectCheck.Checked() {
		ui.form.Synchronize(ui.onConnect)
	}
	// Bring window to foreground — needed when re-launched after auto-update,
	// because the new process is started as a child and Windows places it behind
	// existing windows by default.
	win.SetForegroundWindow(ui.form.Handle())
	win.BringWindowToTop(ui.form.Handle())
	ui.form.Run()
}

func (ui *winUI) connectionPage() TabPage {
	return TabPage{
		Title: "Connection",
		Content: ScrollView{
			Layout: VBox{Spacing: 6},
			Children: []Widget{
				Composite{
					Layout: HBox{Spacing: 6, MarginsZero: true},
					Children: []Widget{
						ImageView{
							AssignTo: &ui.statusDotView,
							MaxSize:  Size{Width: 16, Height: 16},
							MinSize:  Size{Width: 16, Height: 16},
						},
						Label{
							AssignTo: &ui.connectionStatusLabel,
							Text:     "Disconnected",
							Font:     Font{Bold: true},
						},
					},
				},
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
									go ui.fetchAndPopulateHubs()
								}
							},
						},
						Label{Text: "Address:"},
						Composite{
							Layout: HBox{MarginsZero: true, Spacing: 3},
							Children: []Widget{
								LineEdit{
									AssignTo:          &ui.serverEdit,
									StretchFactor:     3,
									OnEditingFinished: func() { go ui.fetchAndPopulateHubs() },
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
						Label{Text: "Hub:"},
						Composite{
							Layout: HBox{MarginsZero: true, Spacing: 3},
							Children: []Widget{
								ComboBox{
									AssignTo:      &ui.hubCombo,
									StretchFactor: 3,
								},
								PushButton{
									Text:      "↻",
									MaxSize:   Size{Width: 30},
									OnClicked: func() { go ui.fetchAndPopulateHubs() },
								},
							},
						},
						Label{Text: "Mode:"},
						ComboBox{
							AssignTo:     &ui.modeCombo,
							Model:        []string{"auto", "direct", "bridge"},
							CurrentIndex: 0,
						},
						Label{Text: "Transport:"},
						ComboBox{
							AssignTo:     &ui.transportCombo,
							Model:        []string{"auto", "udp", "tcp", "reality"},
							CurrentIndex: 0,
						},
					},
				},
				GroupBox{
					Title:  "Config file",
					Layout: HBox{Spacing: 4},
					Children: []Widget{
						ComboBox{
							AssignTo:              &ui.configCombo,
							StretchFactor:         3,
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
						PushButton{
							AssignTo:  &ui.connectBtn,
							Text:      "Connect",
							OnClicked: ui.onConnect,
							MinSize:   Size{Width: 130, Height: 44},
							Font:      Font{Bold: true, PointSize: 12},
						},
						PushButton{
							AssignTo:  &ui.disconnectBtn,
							Text:      "Disconnect",
							Enabled:   false,
							OnClicked: ui.onDisconnect,
							MinSize:   Size{Width: 130, Height: 44},
							Font:      Font{Bold: true, PointSize: 12},
						},
					},
				},
				Label{AssignTo: &ui.statsLabel, Text: ""},
				Composite{
					Layout: HBox{MarginsZero: true, Spacing: 6},
					Children: []Widget{
						LinkLabel{
							StretchFactor: 1,
							Text:          `Bridge mode packet capture: <a href="https://npcap.com/dist/npcap-1.88.exe">Npcap 1.88</a>`,
							OnLinkActivated: func(link *walk.LinkLabelLink) {
								exec.Command("rundll32", "url.dll,FileProtocolHandler", link.URL()).Start()
							},
						},
						PushButton{
							AssignTo:  &ui.npcapBtn,
							Text:      "Install Npcap/WinPcap",
							MaxSize:   Size{Width: 190},
							OnClicked: func() { go ui.onInstallNpcap() },
						},
					},
				},
				LinkLabel{
					AssignTo:        &ui.bmwLabel,
					Text:            "",
					Font:            Font{PointSize: 9},
					MinSize:         Size{Height: 32}, // room for 2 lines (IP/VIN + model detail)
					OnLinkActivated: ui.onBmwLinkActivated,
				},
				Label{
					AssignTo: &ui.batteryLabel,
					Text:     "",
					Font:     Font{PointSize: 9},
				},
				Label{
					AssignTo: &ui.disconnectLabel,
					Text:     "",
					Font:     Font{PointSize: 9},
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
						ComboBox{
							AssignTo: &ui.bridgeNICCombo,
							Model:    listAdapterNames(),
							Editable: true,
						},
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
						Label{Text: "TUN static IP (CIDR):"},
						LineEdit{AssignTo: &ui.tunIPEdit, CueBanner: "e.g. 192.168.100.10/24"},
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
				GroupBox{
					Title:  "Behavior",
					Layout: VBox{Spacing: 6},
					Children: []Widget{
						Composite{
							Layout: HBox{MarginsZero: true, Spacing: 16},
							Children: []Widget{
								CheckBox{
									AssignTo: &ui.autoConnectCheck,
									Text:     "Auto-connect on startup",
								},
								CheckBox{
									AssignTo: &ui.minimizeToTrayCheck,
									Text:     "Minimize to tray on close / minimize",
								},
								HSpacer{},
							},
						},
						CheckBox{
							AssignTo: &ui.startWithWindowsCheck,
							Text:     "Start with Windows (register auto-start task)",
							OnClicked: func() {
								ui.applyStartWithWindows(ui.startWithWindowsCheck.Checked())
							},
						},
						CheckBox{
							AssignTo: &ui.batteryPollingCheck,
							Text:     "Battery polling (SoC & voltage via ENET)",
							Checked:  true,
							OnClicked: func() {
								if !ui.batteryPollingCheck.Checked() {
									if ui.batteryCancel != nil {
										ui.batteryCancel()
										ui.batteryCancel = nil
									}
									_ = ui.batteryLabel.SetText("")
								} else {
									ui.batteryIP = "" // force restart on next ZGW update
								}
							},
						},
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
	if ui.configCombo == nil || ui.suppressConfigReload {
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
	cfg, err := config.ParseClientConfig(path)
	if err != nil {
		walk.MsgBox(ui.form, "Error", "Cannot load config: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	ui.populateFromConfig(cfg)
	ui.configPath = path
	ui.saveLastConfigPath(path)
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
	cfg, err := config.ParseClientConfig(path)
	if err != nil {
		walk.MsgBox(ui.form, "Error", "Cannot load config: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	ui.populateFromConfig(cfg)
	ui.configPath = path
	ui.saveLastConfigPath(path)
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
	if !strings.HasSuffix(strings.ToLower(path), ".toml") {
		path += ".toml"
	}
	cfg := ui.buildConfig()
	if err := config.SaveClientConfig(path, &cfg); err != nil {
		walk.MsgBox(ui.form, "Error", "Cannot save config: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	ui.configPath = path
	ui.saveLastConfigPath(path)
	ui.addConfigToCombo(path)
	_ = ui.configLabel.SetText(path)
}

func (ui *winUI) addConfigToCombo(path string) {
	// Suppress onConfigSelected while we manipulate the combo programmatically.
	// The caller is responsible for populating the fields if needed (e.g.
	// onBrowseConfig calls populateFromConfig directly before calling us).
	ui.suppressConfigReload = true
	defer func() { ui.suppressConfigReload = false }()

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

	// If the previously-used config is not in any search dir, add it to the list.
	lastUsed := ui.readLastConfigPath()
	if lastUsed != "" {
		alreadyFound := false
		for _, e := range found {
			if e.path == lastUsed {
				alreadyFound = true
				break
			}
		}
		if !alreadyFound {
			if _, err := os.Stat(lastUsed); err == nil {
				name := filepath.Base(lastUsed)
				if _, exists := ui.configFilePaths[name]; exists {
					name = filepath.Base(filepath.Dir(lastUsed)) + "/" + name
				}
				ui.configFilePaths[name] = lastUsed
				ui.configNames = append(ui.configNames, name)
				found = append(found, struct{ displayName, path string }{name, lastUsed})
			}
		}
	}

	_ = ui.configCombo.SetModel(ui.configNames)

	// Prefer the last-used config; fall back to auto-selecting when there's exactly one.
	autoIdx := -1
	if lastUsed != "" {
		for i, name := range ui.configNames {
			if ui.configFilePaths[name] == lastUsed {
				autoIdx = i
				break
			}
		}
	}
	if autoIdx < 0 && len(ui.configNames) == 1 {
		autoIdx = 0
	}
	if autoIdx >= 0 {
		_ = ui.configCombo.SetCurrentIndex(autoIdx)
		ui.onConfigSelected()
	}
}

func (ui *winUI) onConnect() {
	cfg := ui.buildConfig()
	if err := cfg.Validate(); err != nil {
		walk.MsgBox(ui.form, "Cannot connect", err.Error(), walk.MsgBoxIconWarning)
		return
	}
	// Reset the last-disconnect counter so a stale value from a previous
	// session is not shown while the new connection is being established.
	ui.lastDisconnect = time.Time{}
	ui.prevConnected = false
	_ = ui.disconnectLabel.SetText("")
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
	// Stop the disconnect timer: prevConnected=false makes the 1s ticker
	// clear the label instead of ticking (runRefreshLoop already exited).
	ui.prevConnected = false
	_ = ui.disconnectLabel.SetText("")
	_ = ui.statusBarItem.SetText("Disconnected")
	_ = ui.connectionStatusLabel.SetText("Disconnected")
	ui.setStatusDot(dotGray)
	_ = ui.statsLabel.SetText("")
	ui.prevStatsTime = time.Time{}
	ui.autoSaveDone = false
	ui.lastLogVersion = 0
	ui.connectBtn.SetEnabled(true)
	ui.disconnectBtn.SetEnabled(false)
}

// ── refresh loop ──────────────────────────────────────────────────────────────

// runRefreshLoop drives all periodic UI updates from a single goroutine.
// walk.Synchronize (equivalent of fyne.Do) is used for all widget mutations.
// maxLogDisplay is the number of lines shown in the log tab.
// Keeping it well below maxLogLines (500) speeds up TextEdit redraws
// and reduces the work done in Synchronize every few seconds.
const maxLogDisplay = 150

func (ui *winUI) runRefreshLoop(ctx context.Context) {
	// 5-second tick: logs update at most every 5 s, and only when new lines
	// have been added (guarded by logVersion).  This keeps the Win32 message
	// queue clear during long-running sessions.
	logTicker := time.NewTicker(5 * time.Second)
	defer logTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ui.refreshCh:
			ui.doRefreshStatus()
		case <-logTicker.C:
			ver := AppLog.Version()
			if ver == ui.lastLogVersion {
				continue // nothing new — skip the expensive SetText
			}
			ui.lastLogVersion = ver
			logs := AppLog.Lines()
			// Display only the most recent lines to keep SetText fast.
			if len(logs) > maxLogDisplay {
				logs = logs[len(logs)-maxLogDisplay:]
			}
			// Windows TextEdit uses \r\n line endings.
			text := strings.Join(logs, "\r\n")
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

	// Capture config for auto-save inside the Synchronize block so widget reads
	// happen on the UI thread before the goroutine is launched.  Calling
	// Synchronize a second time from the goroutine is fire-and-forget in Walk
	// (PostMessage), so cfg would still be zero by the time Save runs.
	// Detect Connected → not-Connected transition and record disconnect time.
	nowConnected := stats.State == vpnclient.StateConnected
	if ui.prevConnected && !nowConnected {
		ui.lastDisconnect = time.Now()
	}
	ui.prevConnected = nowConnected

	var dotColor dotKind
	switch stats.State {
	case vpnclient.StateConnected:
		dotColor = dotGreen
	case vpnclient.StateConnecting:
		dotColor = dotYellow
	default:
		dotColor = dotRed
	}

	// Walk's Synchronize is async (PostMessage) — the closure runs later on the
	// UI thread.  buildConfig() must read widgets there, so we launch the save
	// goroutine from inside the closure, not after it returns.
	ui.form.Synchronize(func() {
		_ = ui.statusBarItem.SetText(statusText)
		_ = ui.statsLabel.SetText(statsText)
		_ = ui.connectionStatusLabel.SetText(statusText)
		ui.setStatusDot(dotColor)

		if stats.State == vpnclient.StateConnected && !ui.autoSaveDone {
			ui.autoSaveDone = true
			cfg := ui.buildConfig()
			go ui.autoSaveConfig(cfg)
		}
	})
}

func (ui *winUI) autoSaveConfig(cfg config.ClientConfig) {
	path := ui.configPath
	if path == "" {
		// Save next to the executable, not in AppData — easier to find and
		// carry with the binary when running from a USB stick or share.
		if exe, err := os.Executable(); err == nil {
			path = filepath.Join(filepath.Dir(exe), "client.toml")
		} else {
			dir, err2 := os.UserConfigDir()
			if err2 != nil {
				return
			}
			path = filepath.Join(dir, "superVPN", "client.toml")
		}
	}
	if err := config.SaveClientConfig(path, &cfg); err == nil {
		log.Printf("config auto-saved to %s", path)
		ui.saveLastConfigPath(path)
		ui.form.Synchronize(func() {
			ui.configPath = path
			_ = ui.configLabel.SetText(path)
			ui.addConfigToCombo(path)
		})
	} else {
		log.Printf("config auto-save failed: %v", err)
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

	hubID := parseHubID(ui.hubCombo.Text())
	if hubID == 0 && ui.pendingHubID != 0 {
		// hubCombo is empty when auto-connect fires before fetchAndPopulateHubs
		// returns; use the hub ID from the last loaded config.
		hubID = ui.pendingHubID
	}
	if hubID == 0 {
		hubID = 1 // absolute fallback
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

	transportItems := []string{"auto", "udp", "tcp", "reality"}
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
		TunIP:     strings.TrimSpace(ui.tunIPEdit.Text()),
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
			NIC:         strings.TrimSpace(ui.bridgeNICCombo.Text()),
			TapName:     strings.TrimSpace(ui.bridgeTAPEdit.Text()),
			SetupMethod: bridgeMethod,
		},
		StatusListen:     strings.TrimSpace(ui.statusListenEdit.Text()),
		Timeout:          strings.TrimSpace(ui.timeoutEdit.Text()),
		MinimizeToTray:        ui.minimizeToTrayCheck.Checked(),
		AutoConnect:           ui.autoConnectCheck.Checked(),
		StartWithWindows:      ui.startWithWindowsCheck.Checked(),
		DisableBatteryPolling: !ui.batteryPollingCheck.Checked(),
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
	ui.pendingHubID = cfg.HubID
	_ = ui.hubCombo.SetText(strconv.Itoa(int(cfg.HubID)))
	go ui.fetchAndPopulateHubs()

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

	transportItems := []string{"auto", "udp", "tcp", "reality"}
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
	_ = ui.bridgeNICCombo.SetText(cfg.Bridge.NIC)
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
	_ = ui.tunIPEdit.SetText(cfg.TunIP)
	_ = ui.statusListenEdit.SetText(cfg.StatusListen)
	_ = ui.timeoutEdit.SetText(cfg.Timeout)
	ui.minimizeToTrayCheck.SetChecked(cfg.MinimizeToTray)
	ui.autoConnectCheck.SetChecked(cfg.AutoConnect)
	ui.startWithWindowsCheck.SetChecked(cfg.StartWithWindows)
	ui.batteryPollingCheck.SetChecked(!cfg.DisableBatteryPolling)
}

// ── connectivity test tab ─────────────────────────────────────────────────────

func (ui *winUI) testPage() TabPage {
	return TabPage{
		Title: "Test",
		Content: ScrollView{
			Layout: VBox{Spacing: 6},
			Children: []Widget{
				PushButton{
					AssignTo:  &ui.testBtn,
					Text:      "▶  Test All Servers",
					OnClicked: func() { go ui.onRunConnTest() },
				},
				TextEdit{
					AssignTo: &ui.testResultEdit,
					ReadOnly: true,
					Font:     Font{Family: "Courier New", PointSize: 9},
					Text: "Press \"Test All Servers\" to check UDP and TCP\r\n" +
						"reachability for each preset server.\r\n\r\n" +
						"UDP  — sent via port 5555 (main VPN port)\r\n" +
						"TCP  — dial port 443 (TLS fallback port)\r\n",
				},
			},
		},
	}
}

func (ui *winUI) onRunConnTest() {
	ui.form.Synchronize(func() {
		ui.testBtn.SetEnabled(false)
		_ = ui.testBtn.SetText("Testing…")
		_ = ui.testResultEdit.SetText("Testing all servers…\r\n\r\n")
	})

	results := make([]ServerTestResult, 0, len(predefinedServers))
	ch := TestAllServers()
	for r := range ch {
		results = append(results, r)
		// Stream partial results as they arrive.
		ui.form.Synchronize(func() {
			_ = ui.testResultEdit.SetText(ui.formatTestResults(results))
		})
	}

	ui.form.Synchronize(func() {
		_ = ui.testBtn.SetText("▶  Test All Servers")
		ui.testBtn.SetEnabled(true)
	})
}

func (ui *winUI) formatTestResults(results []ServerTestResult) string {
	const f = "%-6s  %-22s  %-8s  %-8s  %-8s  %-8s  %s\r\n"
	out := fmt.Sprintf(f, "Name", "Address", "UDP", "UDP+1", "TCP8443", "TCP8444", "Reality443")
	out += strings.Repeat("─", 82) + "\r\n"
	for _, r := range results {
		out += fmt.Sprintf(f, r.Name, r.Addr, r.UDP, r.UDP2, r.TCP, r.TCP2, r.Reality)
	}
	return out
}

// ── Npcap install ─────────────────────────────────────────────────────────────

// updateNpcapButton reflects whether a capture driver is detected, but keeps the
// button ENABLED either way: detection can false-positive on uninstall remnants
// (a lingering SOFTWARE\WinPcap key or npf service with no wpcap.dll), so the
// user must always be able to (re)install. Safe to call from any thread.
func (ui *winUI) updateNpcapButton() {
	installed := pkgtun.NpcapInstalled()
	ui.form.Synchronize(func() {
		if installed {
			_ = ui.npcapBtn.SetText("Npcap ✓ — переустановить")
			_ = ui.npcapBtn.SetToolTipText("Драйвер определён как установленный. Если захват не работает, нажмите для переустановки Npcap/WinPcap.")
		} else {
			_ = ui.npcapBtn.SetText("Install Npcap/WinPcap")
			_ = ui.npcapBtn.SetToolTipText("Установить драйвер захвата (нужен для bridge-режима).")
		}
		ui.npcapBtn.SetEnabled(true)
	})
}

// onInstallNpcap runs in a goroutine: disables the button, runs the installer,
// then refreshes the button state to reflect the result.
// bmwLinkMarkup renders the BMW discovery result as LinkLabel markup with the
// car IP and VIN as clickable links (id "ip" / "vin"). Returns the markup plus
// the raw IP and VIN so the click handler can copy them verbatim.
func bmwLinkMarkup(info *zgw.Info) (markup, ip, vin string) {
	if info == nil {
		return "BMW: not found", "", ""
	}
	if info.VIN == "" {
		return `BMW: <a id="ip">` + info.IP + `</a> (no ZGW response)`, info.IP, ""
	}
	m := `BMW: <a id="ip">` + info.IP + `</a>  <a id="vin">` + info.VIN + `</a>`
	var d string
	add := func(s string) {
		if s == "" {
			return
		}
		if d != "" {
			d += "  "
		}
		d += s
	}
	add(info.Model)
	add(info.Platform)
	if info.PowerKW > 0 {
		add(fmt.Sprintf("%dkW", info.PowerKW))
	}
	add(info.Body)
	if d != "" {
		m += "\n" + d
	}
	return m, info.IP, info.VIN
}

// onBmwLinkActivated copies the clicked car IP or VIN to the clipboard.
func (ui *winUI) onBmwLinkActivated(link *walk.LinkLabelLink) {
	var v string
	switch link.Id() {
	case "ip":
		v = ui.bmwIP
	case "vin":
		v = ui.bmwVIN
	}
	if v == "" {
		return
	}
	_ = walk.Clipboard().SetText(v)
	if ui.statusBarItem != nil {
		_ = ui.statusBarItem.SetText("Скопировано: " + v)
	}
}

// maybeInstallNpcap prompts on first launch when Npcap is missing and, if the
// user agrees, runs the embedded installer. Npcap is only needed for bridge
// mode (direct/WinTun works without it), so it is offered, not forced.
func (ui *winUI) maybeInstallNpcap() {
	if pkgtun.NpcapInstalled() {
		return
	}
	if walk.MsgBox(ui.form, "superVPN — Npcap/WinPcap",
		"Драйвер захвата (Npcap/WinPcap) не установлен — он нужен для режима моста (bridge).\n\n"+
			"Установить сейчас? (для direct-режима он не требуется)",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != win.IDYES {
		return
	}
	go ui.onInstallNpcap()
}

func (ui *winUI) onInstallNpcap() {
	ui.form.Synchronize(func() {
		_ = ui.npcapBtn.SetText("Installing…")
		ui.npcapBtn.SetEnabled(false)
	})
	err := pkgtun.InstallNpcap()
	if err != nil {
		log.Printf("npcap install: %v", err)
	}
	// Re-check installation state regardless of error (installer may have
	// succeeded even if it returned a non-zero exit code on some systems).
	ui.updateNpcapButton()
}

// ── hub discovery ─────────────────────────────────────────────────────────────

// fetchAndPopulateHubs contacts the server and fills hubCombo with the hub list.
// Must be called in a goroutine — it blocks on network I/O.
func (ui *winUI) fetchAndPopulateHubs() {
	addr := ui.serverEdit.Text()
	if addr == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	hubs, err := vpnclient.FetchHubs(ctx, addr)
	if err != nil {
		// Non-fatal: server may be old or unreachable — leave combo as-is.
		log.Printf("hub discovery: %v", err)
		return
	}

	// Build display strings "ID - Name" and remember the raw list.
	items := make([]string, len(hubs))
	for i, h := range hubs {
		items[i] = fmt.Sprintf("%d - %s", h.ID, h.Name)
	}

	ui.form.Synchronize(func() {
		ui.hubInfos = hubs
		_ = ui.hubCombo.SetModel(items)

		// pendingHubID is set when a config is loaded; it takes priority over
		// whatever text the combo currently shows (which may be empty because
		// SetText on an empty-model ComboBox does not persist in Walk).
		targetID := ui.pendingHubID
		if targetID == 0 {
			targetID = parseHubID(ui.hubCombo.Text())
		}
		for i, h := range hubs {
			if h.ID == targetID {
				_ = ui.hubCombo.SetCurrentIndex(i)
				ui.pendingHubID = 0
				return
			}
		}
		// Default to first hub if nothing matched.
		if len(items) > 0 {
			_ = ui.hubCombo.SetCurrentIndex(0)
		}
		ui.pendingHubID = 0
	})
}

// parseHubID extracts a numeric hub ID from the combo text.
// Accepts "7 - den", "7", or any prefix that parses as an integer.
// Returns 0 when the text is empty or unparseable so callers can distinguish
// "not yet determined" from a real hub ID and apply a pendingHubID fallback.
func parseHubID(text string) uint16 {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0
	}
	if idx := strings.Index(text, " - "); idx >= 0 {
		text = strings.TrimSpace(text[:idx])
	}
	n, err := strconv.Atoi(text)
	if err != nil || n <= 0 {
		return 0
	}
	return uint16(n)
}

// applyStartWithWindows registers or removes a Windows Scheduled Task that
// launches this executable at user logon with elevated privileges.
func (ui *winUI) applyStartWithWindows(enable bool) {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("start-with-windows: cannot locate exe: %v", err)
		return
	}
	exe, _ = filepath.EvalSymlinks(exe)

	var script string
	if enable {
		exeQ := strings.ReplaceAll(exe, "'", "''")
		// WindowsIdentity::GetCurrent().Name always returns DOMAIN\Username
		// (or COMPUTERNAME\Username for local accounts), which is the format
		// Task Scheduler expects for both -User and -UserId.  Using $env:USERNAME
		// alone (without domain) can fail to match on some configurations.
		script = fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$who      = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action   = New-ScheduledTaskAction -Execute '%s'
$trigger  = New-ScheduledTaskTrigger -AtLogon -User $who
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 `+
			`-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `+
			`-MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal `+
			`-UserId $who -RunLevel Highest -LogonType Interactive
Register-ScheduledTask -TaskName 'superVPN' `+
			`-Action $action -Trigger $trigger `+
			`-Settings $settings -Principal $principal -Force | Out-Null
Write-Output 'OK'
`, exeQ)
	} else {
		script = `Unregister-ScheduledTask -TaskName 'superVPN' ` +
			`-Confirm:$false -ErrorAction SilentlyContinue; Write-Output 'OK'`
	}

	cmd := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", "-",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		log.Printf("start-with-windows: powershell error: %v: %s", err, result)
		walk.MsgBox(ui.form, "Start with Windows",
			"Failed to update startup task:\n"+result,
			walk.MsgBoxIconWarning)
		return
	}
	action := "registered"
	if !enable {
		action = "removed"
	}
	log.Printf("start-with-windows: task %s (%s)", action, exe)
}

// listAdapterNames returns the friendly names of all network adapters visible
// to the OS, used to populate the Bridge NIC dropdown.
func listAdapterNames() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		// Never offer Radmin VPN (Famatech) etc. as a bridge target.
		if bridge.IsExcludedFromBridge(iface.Name) {
			continue
		}
		names = append(names, iface.Name)
	}
	return names
}

// ── last-used config persistence ──────────────────────────────────────────────

func lastConfigFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "superVPN", ".last_config")
}

// saveLastConfigPath records path so the next launch can restore it.
func (ui *winUI) saveLastConfigPath(path string) {
	f := lastConfigFile()
	if f == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(f), 0755)
	_ = os.WriteFile(f, []byte(path), 0600)
}

// readLastConfigPath returns the path saved by the previous session, or "".
func (ui *winUI) readLastConfigPath() string {
	f := lastConfigFile()
	if f == "" {
		return ""
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// centerWindow moves the main window to the center of the primary monitor.
func (ui *winUI) centerWindow() {
	sw := int(win.GetSystemMetrics(win.SM_CXSCREEN))
	sh := int(win.GetSystemMetrics(win.SM_CYSCREEN))
	b := ui.form.BoundsPixels()
	x := (sw - b.Width) / 2
	y := (sh - b.Height) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	_ = ui.form.SetBoundsPixels(walk.Rectangle{X: x, Y: y, Width: b.Width, Height: b.Height})
}

// ── system tray ───────────────────────────────────────────────────────────────

// setupTray creates the system-tray icon and wires close/minimize intercepts.
// The icon is loaded from icon.png next to the exe when present; otherwise the
// icon already embedded in the exe via rsrc_windows.syso is used as fallback.
func (ui *winUI) setupTray() {
	ni, err := walk.NewNotifyIcon(ui.form)
	if err != nil {
		log.Printf("tray: %v", err)
		return
	}
	ui.notifyIcon = ni

	if ico := ui.loadTrayIcon(); ico != nil {
		_ = ni.SetIcon(ico)
		_ = ui.form.SetIcon(ico) // title bar + taskbar button
	}
	_ = ni.SetToolTip("superVPN — left-click to show")
	_ = ni.SetVisible(true)

	showWindow := func() {
		ui.form.SetVisible(true)
		// Restore from minimised state; Walk's FormBase in this version does
		// not expose WindowState/SetWindowState, so we use Win32 directly.
		win.ShowWindow(ui.form.Handle(), win.SW_RESTORE)
		win.SetForegroundWindow(ui.form.Handle())
	}

	ni.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			showWindow()
		}
	})

	// ni.ContextMenu() returns the icon's own *walk.Menu — add actions to it.
	showAction := walk.NewAction()
	_ = showAction.SetText("Show")
	showAction.Triggered().Attach(showWindow)

	quitAction := walk.NewAction()
	_ = quitAction.SetText("Quit")
	quitAction.Triggered().Attach(func() { walk.App().Exit(0) })

	_ = ni.ContextMenu().Actions().Add(showAction)
	_ = ni.ContextMenu().Actions().Add(walk.NewSeparatorAction())
	_ = ni.ContextMenu().Actions().Add(quitAction)

	// X button → hide to tray instead of quit when minimize_to_tray is set.
	// Also restore the Windows Firewall on real close (not when hiding to tray).
	ui.form.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if ui.minimizeToTrayCheck != nil && ui.minimizeToTrayCheck.Checked() {
			*canceled = true
			ui.form.SetVisible(false)
			return // app keeps running — do NOT restore firewall
		}
		_ = winfirewall.Enable()
	})

	// Minimize button → hide to tray when minimize_to_tray is set.
	// win.IsIconic is the Win32 way; Walk's FormBase does not expose
	// WindowState() in this release.
	ui.form.SizeChanged().Attach(func() {
		if ui.minimizeToTrayCheck != nil && ui.minimizeToTrayCheck.Checked() {
			if win.IsIconic(ui.form.Handle()) {
				ui.form.SetVisible(false)
			}
		}
	})
}

// loadTrayIcon returns a Walk icon for the system tray and window chrome.
// The icon is always loaded from the exe's embedded resource (ID 1, set by
// go-winres simply during the build). This is the only reliable path on
// Windows — loading from a PNG or from the exe file as a whole produces a
// small or wrong result depending on Walk version.
func (ui *winUI) loadTrayIcon() *walk.Icon {
	if ico, err := walk.NewIconFromResourceId(1); err == nil {
		return ico
	}
	return nil
}

// ── status dot ────────────────────────────────────────────────────────────────

type dotKind int

const (
	dotGray   dotKind = iota // disconnected
	dotGreen                 // connected
	dotYellow                // connecting
	dotRed                   // error / reconnecting
)

var dotColors = map[dotKind]color.NRGBA{
	dotGray:   {R: 140, G: 140, B: 140, A: 255},
	dotGreen:  {R: 60, G: 185, B: 80, A: 255},
	dotYellow: {R: 220, G: 180, B: 0, A: 255},
	dotRed:    {R: 210, G: 50, B: 50, A: 255},
}

// setStatusDot updates the status indicator image view with a filled circle
// of the colour matching kind.  Must be called on the UI goroutine.
func (ui *winUI) setStatusDot(kind dotKind) {
	if ui.statusDotView == nil {
		return
	}
	bmp, err := makeDotBitmap(dotColors[kind])
	if err != nil {
		return
	}
	_ = ui.statusDotView.SetImage(bmp)
}

// updateBattery starts or stops battery polling based on the current ZGW info.
// Polls G-series (CLAR) and F-series cars; skips everything else. Must be
// called on the UI goroutine (inside form.Synchronize).
func (ui *winUI) updateBattery(info *zgw.Info) {
	if ui.batteryLabel == nil {
		return
	}
	if ui.batteryPollingCheck != nil && !ui.batteryPollingCheck.Checked() {
		return // polling disabled; OnClicked already stopped any running poll
	}
	newIP, platform := batteryTarget(info)
	if newIP == ui.batteryIP {
		return // same car (or still unsupported series) — keep polling
	}
	if ui.batteryCancel != nil {
		ui.batteryCancel()
		ui.batteryCancel = nil
	}
	ui.batteryIP = newIP
	if newIP == "" {
		_ = ui.batteryLabel.SetText("")
		return
	}
	_ = ui.batteryLabel.SetText("Battery: reading…")
	ctx, cancel := context.WithCancel(context.Background())
	ui.batteryCancel = cancel
	label := ui.batteryLabel
	form := ui.form
	go bmwbattery.StickyPoll(ctx, newIP, platform, 30*time.Second, func(st *bmwbattery.Status) {
		text := "Battery: " + st.String()
		form.Synchronize(func() { _ = label.SetText(text) })
	})
}

// makeDotBitmap returns a 16×16 anti-aliased filled circle bitmap.
func makeDotBitmap(col color.NRGBA) (*walk.Bitmap, error) {
	const size = 16
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	cx, cy := float64(size-1)/2.0, float64(size-1)/2.0
	radius := cx - 1.0 // 1 px inset so the edge anti-aliases cleanly
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist <= radius {
				img.SetNRGBA(x, y, col)
			} else if dist <= radius+1.0 {
				// Soft edge: blend with transparent background.
				alpha := uint8((radius + 1.0 - dist) * float64(col.A))
				img.SetNRGBA(x, y, color.NRGBA{col.R, col.G, col.B, alpha})
			}
		}
	}
	return walk.NewBitmapFromImage(img)
}
