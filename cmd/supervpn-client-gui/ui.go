package main

import (
	"context"
	"image/color"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/atlanteg/supervpn/internal/clientadapter"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/vpnclient"
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
	serverEntry     *widget.Entry
	loginEntry      *widget.Entry
	passwordEntry   *widget.Entry
	hubEntry        *widget.Entry
	modeSelect      *widget.Select
	transportSelect *widget.Select
	configPathLabel *widget.Label

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
	logEntry   *widget.Entry
	logBinding binding.String

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
		container.NewTabItem("Log", ui.buildLogTab()),
	)

	return container.NewBorder(statusBar, nil, nil, nil, tabs)
}

func (ui *mainUI) buildConnectionTab() fyne.CanvasObject {
	ui.serverSelect = widget.NewSelect([]string{}, nil)
	ui.serverEntry = widget.NewEntry()
	ui.serverEntry.SetPlaceHolder("host:port")

	addBtn := widget.NewButton("Add", func() {
		text := strings.TrimSpace(ui.serverEntry.Text)
		if text == "" {
			return
		}
		opts := ui.serverSelect.Options
		for _, o := range opts {
			if o == text {
				ui.serverSelect.SetSelected(text)
				return
			}
		}
		opts = append(opts, text)
		ui.serverSelect.Options = opts
		ui.serverSelect.Refresh()
		ui.serverSelect.SetSelected(text)
	})

	serverRow := container.NewHBox(ui.serverSelect, ui.serverEntry, addBtn)

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

	ui.configPathLabel = widget.NewLabel("")
	browseBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFileOpen(func(f fyne.URIReadCloser, err error) {
			if err != nil || f == nil {
				return
			}
			path := f.URI().Path()
			cfg, err := config.LoadClientConfig(path)
			if err != nil {
				dialog.ShowError(err, ui.win)
				return
			}
			ui.populateFromConfig(cfg)
			ui.configPathLabel.SetText(path)
		}, ui.win)
	})
	configRow := container.NewHBox(widget.NewLabel("Config file:"), browseBtn, ui.configPathLabel)

	ui.connectBtn = widget.NewButton("Connect", ui.onConnect)
	ui.disconnectBtn = widget.NewButton("Disconnect", ui.onDisconnect)
	ui.disconnectBtn.Disable()
	btnRow := container.NewHBox(ui.connectBtn, ui.disconnectBtn)

	return container.NewVBox(form, configRow, btnRow)
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

	return widget.NewForm(
		widget.NewFormItem("FEC K", ui.fecKEntry),
		widget.NewFormItem("FEC R", ui.fecREntry),
		widget.NewFormItem("FEC Delay ms", ui.fecDelayEntry),
		widget.NewFormItem("TLS SNI", ui.tlsSNIEntry),
		widget.NewFormItem("UDP Knock Count", ui.knockCountEntry),
		widget.NewFormItem("UDP Knock Size", ui.knockSizeEntry),
		widget.NewFormItem("UDP Attempts", ui.udpAttemptsEntry),
		widget.NewFormItem("Bridge NIC", ui.bridgeNICEntry),
		widget.NewFormItem("Bridge TAP Name", ui.bridgeTAPEntry),
		widget.NewFormItem("Bridge Method", ui.bridgeMethodEntry),
		widget.NewFormItem("TUN Name", ui.tunNameEntry),
		widget.NewFormItem("Status Listen", ui.statusListenEntry),
		widget.NewFormItem("Timeout", ui.timeoutEntry),
	)
}

func (ui *mainUI) buildLogTab() fyne.CanvasObject {
	ui.logBinding = binding.NewString()
	ui.logEntry = widget.NewMultiLineEntry()
	ui.logEntry.Disable()
	ui.logEntry.Wrapping = fyne.TextWrapBreak

	clearBtn := widget.NewButton("Clear", func() {
		_ = ui.logBinding.Set("")
		ui.logEntry.SetText("")
	})

	scroll := container.NewScroll(ui.logEntry)
	return container.NewBorder(nil, clearBtn, nil, nil, scroll)
}

func (ui *mainUI) onConnect() {
	cfg := ui.buildConfig()

	ui.connectBtn.Disable()
	ui.disconnectBtn.Enable()

	go func() {
		iface, framer, err := clientadapter.OpenAdapter(cfg)
		if err != nil {
			ui.statusLabel.SetText("Error: " + err.Error())
			ui.statusDot.FillColor = color.RGBA{R: 200, A: 255}
			canvas.Refresh(ui.statusDot)
			ui.connectBtn.Enable()
			ui.disconnectBtn.Disable()
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

		c := vpnclient.New(cfg, iface, framer)
		ui.client = c
		c.OnChange(func() { ui.refreshStatus() })
		c.Start(ctx)
	}()
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

	ui.statusDot.FillColor = dotColor
	canvas.Refresh(ui.statusDot)
	ui.statusLabel.SetText(labelText)

	logs := c.Logs()
	ui.logEntry.SetText(strings.Join(logs, "\n"))
}

func (ui *mainUI) buildConfig() config.ClientConfig {
	server := strings.TrimSpace(ui.serverEntry.Text)
	if server == "" {
		server = ui.serverSelect.Selected
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
		StatusListen: strings.TrimSpace(ui.statusListenEntry.Text),
		Timeout:      strings.TrimSpace(ui.timeoutEntry.Text),
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
}
