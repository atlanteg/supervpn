//go:build !windows || (windows && fyne)

package main

import (
	"context"
	"fmt"
	"image/color"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/atlanteg/supervpn/internal/clientadapter"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/vpnclient"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)


type mainUI struct {
	app fyne.App
	win fyne.Window

	client        *vpnclient.Client
	framer        interface{ Close() error }
	connectCtx    context.Context
	connectCancel context.CancelFunc

	// connection tab widgets
	serverSelect    *widget.Select
	serverAddrs     map[string]string // display name → address
	serverEntry     *widget.Entry
	loginEntry      *widget.Entry
	passwordEntry   *widget.Entry
	hubEntry        *widget.Entry
	modeSelect      *widget.Select
	transportSelect *widget.Select
	configSelect    *widget.Select
	configFilePaths map[string]string // display name (basename) → full path
	configPathLabel *widget.Label
	configPath      string // path of currently loaded/saved config file
	statsLabel      *widget.Label

	// for speed calculation in refreshStatus
	prevBytesRx   uint64
	prevBytesTx   uint64
	prevStatsTime time.Time
	autoSaveDone  bool // auto-saved once per connect session
	npcapBtn      *widget.Button // Windows-only: Install Npcap

	// refreshCh is a 1-slot channel used to coalesce rapid OnChange signals
	// so the UI goroutine is never flooded by high-frequency VPN events.
	refreshCh      chan struct{}
	lastLogVersion uint64 // last logVersion rendered to the log tab

	// advanced tab widgets
	fecKEntry         *widget.Entry
	fecREntry         *widget.Entry
	fecDelayEntry     *widget.Entry
	tlsSNIEntry       *widget.Entry
	knockCountEntry   *widget.Entry
	knockSizeEntry    *widget.Entry
	udpAttemptsEntry  *widget.Entry
	bridgeNICEntry    *widget.Entry
	bridgeTAPEntry    *widget.Entry
	bridgeMethodEntry *widget.Select
	tunNameEntry      *widget.Entry
	statusListenEntry *widget.Entry
	timeoutEntry      *widget.Entry

	// status bar
	statusDot   *canvas.Rectangle
	statusLabel *widget.Label

	// log tab
	logEntry *widget.Entry

	// test tab
	testEntry *widget.Entry
	testBtn   *widget.Button

	// advanced tab – behavior
	minimizeToTrayCheck *widget.Check
	autoConnectCheck    *widget.Check

	connectBtn    *widget.Button
	disconnectBtn *widget.Button
}

func newMainUI(a fyne.App, w fyne.Window) *mainUI {
	return &mainUI{app: a, win: w}
}

func (ui *mainUI) build() fyne.CanvasObject {
	ui.statusDot = canvas.NewRectangle(color.Gray{Y: 128})
	ui.statusDot.SetMinSize(fyne.NewSize(16, 16))
	ui.statusLabel = widget.NewLabel("Disconnected")

	statusBar := container.NewHBox(ui.statusDot, ui.statusLabel)

	tabs := container.NewAppTabs(
		container.NewTabItem("Connection", ui.buildConnectionTab()),
		container.NewTabItem("Advanced", ui.buildAdvancedTab()),
		container.NewTabItem("Test", ui.buildTestTab()),
		container.NewTabItem("Log", ui.buildLogTab()),
	)

	return container.NewBorder(statusBar, nil, nil, nil, tabs)
}

func (ui *mainUI) buildConnectionTab() fyne.CanvasObject {
	// Populate predefined server map and dropdown names.
	ui.serverAddrs = make(map[string]string)
	names := make([]string, 0, len(predefinedServers))
	for _, s := range predefinedServers {
		ui.serverAddrs[s.name] = s.addr
		names = append(names, s.name)
	}

	ui.serverEntry = widget.NewEntry()
	ui.serverEntry.SetPlaceHolder("host:port")

	ui.serverSelect = widget.NewSelect(names, func(name string) {
		if addr, ok := ui.serverAddrs[name]; ok {
			ui.serverEntry.SetText(addr)
		}
	})

	addBtn := widget.NewButton("Add", func() {
		text := strings.TrimSpace(ui.serverEntry.Text)
		if text == "" {
			return
		}
		if _, exists := ui.serverAddrs[text]; exists {
			ui.serverSelect.SetSelected(text)
			return
		}
		ui.serverAddrs[text] = text
		opts := append(ui.serverSelect.Options, text)
		ui.serverSelect.Options = opts
		ui.serverSelect.Refresh()
		ui.serverSelect.SetSelected(text)
	})

	serverRow := container.NewBorder(nil, nil, ui.serverSelect, addBtn, ui.serverEntry)

	ui.loginEntry = widget.NewEntry()
	ui.passwordEntry = widget.NewPasswordEntry()

	ui.hubEntry = widget.NewEntry()
	ui.hubEntry.SetText("1")

	ui.modeSelect = widget.NewSelect([]string{"auto", "direct", "bridge"}, nil)
	ui.modeSelect.SetSelected("auto")

	ui.transportSelect = widget.NewSelect([]string{"auto", "udp", "tcp"}, nil)
	ui.transportSelect.SetSelected("auto")

	form := widget.NewForm(
		widget.NewFormItem("Server", serverRow),
		widget.NewFormItem("Login", ui.loginEntry),
		widget.NewFormItem("Password", ui.passwordEntry),
		widget.NewFormItem("Hub ID", ui.hubEntry),
		widget.NewFormItem("Mode", ui.modeSelect),
		widget.NewFormItem("Transport", ui.transportSelect),
	)

	// Config file selector — populated from *.toml files next to the binary.
	ui.configFilePaths = make(map[string]string)
	ui.configSelect = widget.NewSelect(nil, func(name string) {
		path, ok := ui.configFilePaths[name]
		if !ok {
			return
		}
		cfg, err := config.ParseClientConfig(path)
		if err != nil {
			dialog.ShowError(err, ui.win)
			return
		}
		ui.populateFromConfig(cfg)
		ui.configPath = path
		ui.saveLastConfigPref(path)
		ui.configPathLabel.SetText(filepath.Base(path))
	})
	ui.configSelect.PlaceHolder = "— select config —"

	browseBtn := widget.NewButton("Browse…", func() {
		dialog.ShowFileOpen(func(f fyne.URIReadCloser, err error) {
			if err != nil || f == nil {
				return
			}
			path := f.URI().Path()
			cfg, err := config.ParseClientConfig(path)
			if err != nil {
				dialog.ShowError(err, ui.win)
				return
			}
			ui.populateFromConfig(cfg)
			ui.configPath = path
			ui.saveLastConfigPref(path)
			// Add the browsed file to the dropdown if not already there.
			name := filepath.Base(path)
			if _, exists := ui.configFilePaths[name]; !exists {
				ui.configFilePaths[name] = path
				ui.configSelect.Options = append(ui.configSelect.Options, name)
				ui.configSelect.Refresh()
			}
			ui.configSelect.SetSelected(name)
			ui.configPathLabel.SetText(path)
		}, ui.win)
	})
	saveBtn := widget.NewButton("Save…", func() {
		// Read widget state here — OnClicked runs on the main goroutine, so
		// all widget fields are guaranteed to reflect what the user entered.
		// The ShowFileSave callback may run on a different goroutine, so we
		// capture cfg by value now rather than reading widgets inside it.
		cfg := ui.buildConfig()

		dialog.ShowFileSave(func(f fyne.URIWriteCloser, err error) {
			if err != nil || f == nil {
				return
			}
			defer f.Close()
			path := f.URI().Path()
			if !strings.HasSuffix(strings.ToLower(path), ".toml") {
				path += ".toml"
			}

			// Write directly to the handle the dialog gave us.
			// Closing f and re-opening with os.Create causes an empty file on
			// macOS because the OS file-access grant expires with the first close.
			if encErr := config.WriteClientConfig(f, &cfg); encErr != nil {
				fyne.Do(func() { dialog.ShowError(encErr, ui.win) })
				return
			}

			ui.saveLastConfigPref(path)
			fyne.Do(func() {
				ui.configPath = path
				name := filepath.Base(path)
				if _, exists := ui.configFilePaths[name]; !exists {
					ui.configFilePaths[name] = path
					ui.configSelect.Options = append(ui.configSelect.Options, name)
					ui.configSelect.Refresh()
				}
				ui.configSelect.SetSelected(name)
				ui.configPathLabel.SetText(path)
			})
		}, ui.win)
	})

	ui.configPathLabel = widget.NewLabel("")
	ui.configPathLabel.Wrapping = fyne.TextTruncate

	// Layout: [dropdown expands] [Browse…] [Save…]
	configRow := container.NewBorder(nil, nil, nil,
		container.NewHBox(browseBtn, saveBtn),
		ui.configSelect,
	)

	ui.connectBtn = widget.NewButton("Connect", ui.onConnect)
	ui.disconnectBtn = widget.NewButton("Disconnect", ui.onDisconnect)
	ui.disconnectBtn.Disable()
	btnRow := container.NewHBox(ui.connectBtn, ui.disconnectBtn)

	ui.statsLabel = widget.NewLabel("")

	rows := []fyne.CanvasObject{form, configRow, ui.configPathLabel, btnRow, ui.statsLabel}
	// Npcap is Windows-only (bridge mode on macOS uses the kernel TAP directly).
	if runtime.GOOS == "windows" {
		npcapURL, _ := url.Parse("https://npcap.com/dist/npcap-1.88.exe")
		ui.npcapBtn = widget.NewButton("Install Npcap", func() {
			ui.npcapBtn.SetText("Installing…")
			ui.npcapBtn.Disable()
			go func() {
				pkgtun.InstallNpcap()
				ui.updateNpcapBtn()
			}()
		})
		ui.updateNpcapBtn()
		rows = append(rows, container.NewHBox(
			widget.NewLabel("Bridge mode packet capture:"),
			widget.NewHyperlink("Npcap 1.88", npcapURL),
			ui.npcapBtn,
		))
	}
	return container.NewVBox(rows...)
}

func (ui *mainUI) buildAdvancedTab() fyne.CanvasObject {
	ui.fecKEntry = widget.NewEntry()
	ui.fecKEntry.SetText("4")
	ui.fecREntry = widget.NewEntry()
	ui.fecREntry.SetText("2")
	ui.fecDelayEntry = widget.NewEntry()
	ui.fecDelayEntry.SetText("100")
	ui.tlsSNIEntry = widget.NewEntry()
	ui.knockCountEntry = widget.NewEntry()
	ui.knockCountEntry.SetText("3")
	ui.knockSizeEntry = widget.NewEntry()
	ui.knockSizeEntry.SetText("16")
	ui.udpAttemptsEntry = widget.NewEntry()
	ui.udpAttemptsEntry.SetText("3")
	ui.bridgeNICEntry = widget.NewEntry()
	ui.bridgeTAPEntry = widget.NewEntry()
	ui.bridgeMethodEntry = widget.NewSelect([]string{"netbridge", "hyperv"}, nil)
	ui.bridgeMethodEntry.SetSelected("netbridge")
	ui.tunNameEntry = widget.NewEntry()
	ui.tunNameEntry.SetText("supervpn")
	ui.statusListenEntry = widget.NewEntry()
	ui.statusListenEntry.SetPlaceHolder("127.0.0.1:9191")
	ui.timeoutEntry = widget.NewEntry()
	ui.timeoutEntry.SetPlaceHolder("30s")

	items := []*widget.FormItem{
		widget.NewFormItem("FEC K", ui.fecKEntry),
		widget.NewFormItem("FEC R", ui.fecREntry),
		widget.NewFormItem("FEC Delay ms", ui.fecDelayEntry),
		widget.NewFormItem("TLS SNI", ui.tlsSNIEntry),
		widget.NewFormItem("UDP Knock Count", ui.knockCountEntry),
		widget.NewFormItem("UDP Knock Size", ui.knockSizeEntry),
		widget.NewFormItem("UDP Attempts", ui.udpAttemptsEntry),
		widget.NewFormItem("Bridge NIC", ui.bridgeNICEntry),
	}
	if runtime.GOOS == "windows" {
		// TAP adapter name and bridge setup method are Windows-only concepts.
		items = append(items,
			widget.NewFormItem("Bridge TAP Name", ui.bridgeTAPEntry),
			widget.NewFormItem("Bridge Method", ui.bridgeMethodEntry),
		)
	}
	items = append(items,
		widget.NewFormItem("TUN Name", ui.tunNameEntry),
		widget.NewFormItem("Status Listen", ui.statusListenEntry),
		widget.NewFormItem("Timeout", ui.timeoutEntry),
	)

	ui.minimizeToTrayCheck = widget.NewCheck("Minimize to tray on close / minimize", nil)
	items = append(items, widget.NewFormItem("Behavior", ui.minimizeToTrayCheck))

	ui.autoConnectCheck = widget.NewCheck("Auto-connect on startup", nil)
	items = append(items, widget.NewFormItem("", ui.autoConnectCheck))

	return widget.NewForm(items...)
}

func (ui *mainUI) buildLogTab() fyne.CanvasObject {
	ui.logEntry = widget.NewMultiLineEntry()
	// Do NOT call Disable() — it renders text in grey. The entry is
	// effectively read-only because the 1s ticker overwrites any edits.
	ui.logEntry.Wrapping = fyne.TextWrapBreak

	clearBtn := widget.NewButton("Clear", func() {
		ui.logEntry.SetText("")
	})

	scroll := container.NewScroll(ui.logEntry)
	return container.NewBorder(nil, clearBtn, nil, nil, scroll)
}

func (ui *mainUI) buildTestTab() fyne.CanvasObject {
	ui.testEntry = widget.NewMultiLineEntry()
	ui.testEntry.Wrapping = fyne.TextWrapBreak
	ui.testEntry.SetPlaceHolder("Press ▶ Test All Servers to check UDP/TCP reachability for each preset server.")

	ui.testBtn = widget.NewButton("▶ Test All Servers", ui.onRunConnTest)

	scroll := container.NewScroll(ui.testEntry)
	return container.NewBorder(nil, ui.testBtn, nil, nil, scroll)
}

func (ui *mainUI) onRunConnTest() {
	ui.testBtn.SetText("Testing…")
	ui.testBtn.Disable()
	fyne.Do(func() { ui.testEntry.SetText("Running connectivity tests…\n") })

	go func() {
		var results []ServerTestResult

		for r := range TestAllServers() {
			results = append(results, r)
			text := formatTestResults(results)
			fyne.Do(func() { ui.testEntry.SetText(text) })
		}

		fyne.Do(func() {
			ui.testBtn.SetText("▶ Test All Servers")
			ui.testBtn.Enable()
		})
	}()
}

func formatTestResults(rows []ServerTestResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-20s  %-26s  %-14s  %s\n", "Server", "Address", "UDP", "TCP"))
	sb.WriteString(strings.Repeat("─", 78) + "\n")
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("%-20s  %-26s  %-14s  %s\n", r.Name, r.Addr, r.UDP, r.TCP))
	}
	return sb.String()
}

func (ui *mainUI) onConnect() {
	cfg := ui.buildConfig()

	if err := cfg.Validate(); err != nil {
		dialog.ShowError(err, ui.win)
		return
	}

	ui.connectBtn.Disable()
	ui.disconnectBtn.Enable()

	go func() {
		iface, framer, adapterMode, err := clientadapter.OpenAdapter(cfg)
		if err != nil {
			// Button handlers run on the main goroutine; here we're in a
			// background goroutine, so all widget/canvas mutations need fyne.Do.
			fyne.Do(func() {
				ui.statusLabel.SetText("Error: " + err.Error())
				ui.statusDot.FillColor = color.RGBA{R: 200, A: 255}
				canvas.Refresh(ui.statusDot)
				ui.connectBtn.Enable()
				ui.disconnectBtn.Disable()
			})
			return
		}
		ui.framer = framer

		ctx, cancel := context.WithCancel(context.Background())
		ui.connectCtx = ctx
		ui.connectCancel = cancel

		// Persist server address so the update checker can derive a mirror URL.
		if cfg.Server != "" {
			ui.app.Preferences().SetString("last_server", cfg.Server)
		}

		c := vpnclient.New(cfg, iface, framer, adapterMode)
		ui.client = c

		// OnChange fires from VPN goroutines on every log line — potentially
		// hundreds of times per second. Use a 1-slot channel to coalesce rapid
		// signals so we never flood the UI thread.
		ui.refreshCh = make(chan struct{}, 1)
		c.OnChange(func() {
			select {
			case ui.refreshCh <- struct{}{}:
			default: // already pending, drop duplicate
			}
		})

		go ui.runRefreshLoop(ctx)
		c.Start(ctx)
	}()
}

// maxLogDisplay is the number of lines shown in the log tab.
// Capping it well below maxLogLines (500) keeps fyne.Do/SetText fast
// and prevents the renderer from stalling during long-running sessions.
const maxLogDisplay = 150

// runRefreshLoop drives all periodic UI updates from a single goroutine so the
// main thread is never called from multiple VPN goroutines simultaneously.
//
//   - State / stats bar: updated on every coalesced OnChange signal (fast path).
//   - Log text:          updated on a 5-second ticker, skipped when nothing
//     has been logged since the last update (guarded by logVersion).
func (ui *mainUI) runRefreshLoop(ctx context.Context) {
	logTicker := time.NewTicker(5 * time.Second)
	defer logTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ui.refreshCh:
			ui.refreshStatus()
		case <-logTicker.C:
			c := ui.client
			if c == nil {
				continue
			}
			ver := c.LogVersion()
			if ver == ui.lastLogVersion {
				continue // nothing new — skip the expensive SetText
			}
			ui.lastLogVersion = ver
			logs := c.Logs()
			// Display only the most recent lines to keep SetText fast.
			if len(logs) > maxLogDisplay {
				logs = logs[len(logs)-maxLogDisplay:]
			}
			text := strings.Join(logs, "\n")
			fyne.Do(func() { ui.logEntry.SetText(text) })
		}
	}
}

func (ui *mainUI) autoSaveConfig() {
	// buildConfig and configPath must be read on the main goroutine.
	// Use a buffered channel so this goroutine blocks until fyne.Do runs,
	// regardless of whether fyne.Do is synchronous or fire-and-forget.
	type snap struct {
		cfg  config.ClientConfig
		path string
	}
	ch := make(chan snap, 1)
	fyne.Do(func() { ch <- snap{cfg: ui.buildConfig(), path: ui.configPath} })
	s := <-ch

	path := s.path
	if path == "" {
		// Save next to the executable — same as the Walk GUI, easy to find
		// and portable when running from a USB stick or a shared folder.
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
	if err := config.SaveClientConfig(path, &s.cfg); err == nil {
		ui.saveLastConfigPref(path)
		fyne.Do(func() {
			ui.configPath = path
			ui.configPathLabel.SetText(path)
		})
	}
}

// initConfigSelect scans several directories for *.toml files and populates
// the config dropdown. Directories searched (in order):
//  1. The directory containing the executable (works for both AppBundles and CLI installs)
//  2. os.UserConfigDir()/superVPN/ (auto-save location after a successful connect)
//  3. os.UserHomeDir() (default save-dialog location)
//
// If exactly one file is found across all directories it is auto-selected and loaded.
// Called from main() on the main goroutine after build(), so direct widget access is
// safe without fyne.Do.
func (ui *mainUI) initConfigSelect() {
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

	// Disambiguate entries that share the same basename (e.g. client.toml in two dirs).
	baseCount := map[string]int{}
	for _, e := range found {
		baseCount[e.displayName]++
	}
	for i, e := range found {
		if baseCount[e.displayName] > 1 {
			found[i].displayName = filepath.Base(filepath.Dir(e.path)) + "/" + e.displayName
		}
	}

	names := make([]string, 0, len(found))
	for _, e := range found {
		ui.configFilePaths[e.displayName] = e.path
		names = append(names, e.displayName)
	}

	// If the previously-used config isn't in any search dir, add it to the list.
	lastUsed := ui.app.Preferences().String("last_config")
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
				names = append(names, name)
			}
		}
	}

	ui.configSelect.Options = names
	ui.configSelect.Refresh()

	// Prefer the last-used config; fall back to auto-selecting when there's exactly one.
	autoSelect := ""
	if lastUsed != "" {
		for name, path := range ui.configFilePaths {
			if path == lastUsed {
				autoSelect = name
				break
			}
		}
	}
	if autoSelect == "" && len(names) == 1 {
		autoSelect = names[0]
	}
	if autoSelect != "" {
		ui.configSelect.SetSelected(autoSelect)
	}
}

func (ui *mainUI) onDisconnect() {
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
	ui.statusDot.FillColor = color.Gray{Y: 128}
	canvas.Refresh(ui.statusDot)
	ui.statusLabel.SetText("Disconnected")
	ui.statsLabel.SetText("")
	ui.prevStatsTime = time.Time{}
	ui.autoSaveDone = false
	ui.lastLogVersion = 0
	ui.connectBtn.Enable()
	ui.disconnectBtn.Disable()
}

func (ui *mainUI) refreshStatus() {
	c := ui.client
	if c == nil {
		return
	}
	stats := c.Stats()

	var dotColor color.Color
	var labelText string
	switch stats.State {
	case vpnclient.StateConnected:
		dotColor = color.RGBA{G: 180, A: 255}
		labelText = "Connected — " + stats.Transport + " → " + stats.Server
		if stats.AdapterMode != "" {
			labelText += " | " + stats.AdapterMode
		}
	case vpnclient.StateConnecting:
		dotColor = color.RGBA{R: 220, G: 180, A: 255}
		labelText = "Connecting..."
	default:
		dotColor = color.RGBA{R: 200, A: 255}
		labelText = "Reconnecting..."
		if stats.LastError != "" {
			labelText += " (" + stats.LastError + ")"
		}
	}

	// Compute stats text before entering the main thread (no Fyne API calls here).
	var statsText string
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

	// Fyne 2.7+ requires ALL widget/canvas mutations on the main thread.
	// Batch everything into one fyne.Do to minimise scheduling overhead.
	fyne.Do(func() {
		ui.statusDot.FillColor = dotColor
		canvas.Refresh(ui.statusDot)
		ui.statusLabel.SetText(labelText)
		ui.statsLabel.SetText(statsText)
	})

	// Auto-save config once on first successful connect.
	if stats.State == vpnclient.StateConnected && !ui.autoSaveDone {
		ui.autoSaveDone = true
		go ui.autoSaveConfig()
	}
	// Log text is updated on a 1s ticker in runRefreshLoop — not here.
	// Joining 500 lines + SetText on every OnChange event would flood the UI.
}

func (ui *mainUI) buildConfig() config.ClientConfig {
	server := strings.TrimSpace(ui.serverEntry.Text)
	if server == "" {
		selected := ui.serverSelect.Selected
		if addr, ok := ui.serverAddrs[selected]; ok {
			server = addr
		} else {
			server = selected
		}
	}

	hubID := uint16(1)
	if n, err := strconv.Atoi(ui.hubEntry.Text); err == nil && n > 0 {
		hubID = uint16(n)
	}

	fecK := 4
	if n, err := strconv.Atoi(ui.fecKEntry.Text); err == nil && n > 0 {
		fecK = n
	}
	fecR := 2
	if n, err := strconv.Atoi(ui.fecREntry.Text); err == nil && n >= 0 {
		fecR = n
	}
	fecDelay := 100
	if n, err := strconv.Atoi(ui.fecDelayEntry.Text); err == nil && n >= 0 {
		fecDelay = n
	}
	knockCount := 3
	if n, err := strconv.Atoi(ui.knockCountEntry.Text); err == nil && n > 0 {
		knockCount = n
	}
	knockSize := 16
	if n, err := strconv.Atoi(ui.knockSizeEntry.Text); err == nil && n > 0 {
		knockSize = n
	}
	udpAttempts := 3
	if n, err := strconv.Atoi(ui.udpAttemptsEntry.Text); err == nil && n > 0 {
		udpAttempts = n
	}

	transportVal := ui.transportSelect.Selected
	if transportVal == "auto" {
		transportVal = ""
	}
	modeVal := ui.modeSelect.Selected
	if modeVal == "auto" {
		modeVal = ""
	}

	cfg := config.ClientConfig{
		Server:    server,
		HubID:     hubID,
		Login:     ui.loginEntry.Text,
		Password:  ui.passwordEntry.Text,
		Transport: transportVal,
		Mode:      modeVal,
		TunName:   strings.TrimSpace(ui.tunNameEntry.Text),
		FEC: config.FECConfig{
			K:           fecK,
			R:           fecR,
			RepairDelay: fecDelay,
		},
		TLS: config.TLSClientConfig{
			SNI: strings.TrimSpace(ui.tlsSNIEntry.Text),
		},
		UDP: config.UDPConfig{
			KnockCount: knockCount,
			KnockSize:  knockSize,
			Attempts:   udpAttempts,
		},
		Bridge: config.BridgeConfig{
			NIC:         strings.TrimSpace(ui.bridgeNICEntry.Text),
			TapName:     strings.TrimSpace(ui.bridgeTAPEntry.Text),
			SetupMethod: ui.bridgeMethodEntry.Selected,
		},
		StatusListen:   strings.TrimSpace(ui.statusListenEntry.Text),
		Timeout:        strings.TrimSpace(ui.timeoutEntry.Text),
		MinimizeToTray: ui.minimizeToTrayCheck.Checked,
		AutoConnect:    ui.autoConnectCheck.Checked,
	}

	cfg.FEC = cfg.FEC.WithDefaults()
	cfg.UDP = cfg.UDP.WithDefaults()
	cfg.Bridge = cfg.Bridge.WithDefaults()

	return cfg
}

func (ui *mainUI) populateFromConfig(cfg *config.ClientConfig) {
	ui.serverEntry.SetText(cfg.Server)
	ui.loginEntry.SetText(cfg.Login)
	ui.passwordEntry.SetText(cfg.Password)
	ui.hubEntry.SetText(strconv.Itoa(int(cfg.HubID)))

	mode := cfg.Mode
	if mode == "" {
		mode = "auto"
	}
	ui.modeSelect.SetSelected(mode)

	transport := cfg.Transport
	if transport == "" {
		transport = "auto"
	}
	ui.transportSelect.SetSelected(transport)

	if cfg.FEC.K > 0 {
		ui.fecKEntry.SetText(strconv.Itoa(cfg.FEC.K))
	}
	if cfg.FEC.R > 0 {
		ui.fecREntry.SetText(strconv.Itoa(cfg.FEC.R))
	}
	if cfg.FEC.RepairDelay > 0 {
		ui.fecDelayEntry.SetText(strconv.Itoa(cfg.FEC.RepairDelay))
	}
	ui.tlsSNIEntry.SetText(cfg.TLS.SNI)
	if cfg.UDP.KnockCount > 0 {
		ui.knockCountEntry.SetText(strconv.Itoa(cfg.UDP.KnockCount))
	}
	if cfg.UDP.KnockSize > 0 {
		ui.knockSizeEntry.SetText(strconv.Itoa(cfg.UDP.KnockSize))
	}
	if cfg.UDP.Attempts > 0 {
		ui.udpAttemptsEntry.SetText(strconv.Itoa(cfg.UDP.Attempts))
	}
	ui.bridgeNICEntry.SetText(cfg.Bridge.NIC)
	ui.bridgeTAPEntry.SetText(cfg.Bridge.TapName)
	if cfg.Bridge.SetupMethod != "" {
		ui.bridgeMethodEntry.SetSelected(cfg.Bridge.SetupMethod)
	}
	if cfg.TunName != "" {
		ui.tunNameEntry.SetText(cfg.TunName)
	}
	ui.statusListenEntry.SetText(cfg.StatusListen)
	ui.timeoutEntry.SetText(cfg.Timeout)
	ui.minimizeToTrayCheck.SetChecked(cfg.MinimizeToTray)
	ui.autoConnectCheck.SetChecked(cfg.AutoConnect)
}

// saveLastConfigPref persists path so the next launch can restore it.
// Uses Fyne's cross-platform preferences store (plist on macOS, registry on Windows).
func (ui *mainUI) saveLastConfigPref(path string) {
	ui.app.Preferences().SetString("last_config", path)
}

// updateNpcapBtn sets the Install Npcap button state based on whether Npcap
// is already installed.  Safe to call from any goroutine — Fyne widgets are
// thread-safe.  No-op when npcapBtn is nil (non-Windows build or not yet created).
func (ui *mainUI) updateNpcapBtn() {
	if ui.npcapBtn == nil {
		return
	}
	if pkgtun.NpcapInstalled() {
		ui.npcapBtn.SetText("Npcap ✓")
		ui.npcapBtn.Disable()
	} else {
		ui.npcapBtn.SetText("Install Npcap")
		ui.npcapBtn.Enable()
	}
}
