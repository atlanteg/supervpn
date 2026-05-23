//go:build windows

// Stripped-down superVPN client pre-configured for the seema hub.
// Shows only a connection status indicator — no settings, no tabs, no buttons.
package main

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/clientadapter"
	"github.com/atlanteg/supervpn/internal/config"
	"github.com/atlanteg/supervpn/internal/update"
	"github.com/atlanteg/supervpn/internal/vpnclient"
	"github.com/atlanteg/supervpn/internal/winfirewall"
	"github.com/atlanteg/supervpn/internal/zgw"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

var (
	_user32         = windows.NewLazySystemDLL("user32.dll")
	_getWindowTextW = _user32.NewProc("GetWindowTextW")
)

func getWindowText(hwnd win.HWND) string {
	var buf [512]uint16
	_getWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf[:])
}

// version is set at build time via -ldflags "-X main.version=bN".
var version = "dev"

// Hardcoded connection parameters — no user-visible config.
const (
	seemaServer   = "81.27.241.25:5555"
	seemaHubID    = 2
	seemaLogin    = "seema"
	seemaPassword = "cApIb@!"
)

// ── single-instance ───────────────────────────────────────────────────────────

const _mutexName = "Global\\superVPN-seema-client"

var _mutexHandle windows.Handle

func acquireSingleInstance() bool {
	name, err := windows.UTF16PtrFromString(_mutexName)
	if err != nil {
		return true
	}
	h, err := windows.CreateMutex(nil, false, name)
	switch err {
	case nil:
		_mutexHandle = h
		return true
	case windows.ERROR_ALREADY_EXISTS:
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		bringExistingToFront()
		return false
	default:
		return true
	}
}

func bringExistingToFront() {
	cb := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		if strings.HasPrefix(getWindowText(win.HWND(hwnd)), "seema") {
			win.ShowWindow(win.HWND(hwnd), win.SW_RESTORE)
			win.SetForegroundWindow(win.HWND(hwnd))
			return 0
		}
		return 1
	})
	_ = windows.EnumWindows(cb, nil)
}

// ── logging ───────────────────────────────────────────────────────────────────

func openLogFile() *os.File {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	logDir := filepath.Join(dir, "superVPN")
	_ = os.MkdirAll(logDir, 0755)
	f, err := os.OpenFile(filepath.Join(logDir, "seema.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil
	}
	fmt.Fprintf(f, "\n=== seema %s started %s ===\n", version, time.Now().Format(time.RFC3339))
	return f
}

func writeCrashReport(r interface{}) {
	dir, _ := os.UserConfigDir()
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.Create(filepath.Join(dir, "superVPN", "seema-crash.txt"))
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "seema %s crashed at %s\n\npanic: %v\n\n%s\n",
		version, time.Now().Format(time.RFC3339), r, debug.Stack())
}

// ── elevation ─────────────────────────────────────────────────────────────────

func ensureAdmin() {
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	args := ""
	if len(os.Args) > 1 {
		for i, a := range os.Args[1:] {
			if i > 0 {
				args += " "
			}
			args += syscall.EscapeArg(a)
		}
	}
	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	var argsPtr *uint16
	if args != "" {
		argsPtr, _ = syscall.UTF16PtrFromString(args)
	}
	if err := windows.ShellExecute(0, verbPtr, exePtr, argsPtr, nil, windows.SW_NORMAL); err == nil {
		os.Exit(0)
	}
}

// ── dot indicator ─────────────────────────────────────────────────────────────

type dotKind int

const (
	dotGray   dotKind = iota
	dotGreen
	dotYellow
	dotRed
)

var dotColors = map[dotKind]color.NRGBA{
	dotGray:   {R: 140, G: 140, B: 140, A: 255},
	dotGreen:  {R: 60, G: 185, B: 80, A: 255},
	dotYellow: {R: 220, G: 180, B: 0, A: 255},
	dotRed:    {R: 210, G: 50, B: 50, A: 255},
}

func makeDotBitmap(col color.NRGBA) (*walk.Bitmap, error) {
	const size = 16
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	cx, cy := float64(size-1)/2.0, float64(size-1)/2.0
	radius := cx - 1.0
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist <= radius {
				img.SetNRGBA(x, y, col)
			} else if dist <= radius+1.0 {
				alpha := uint8((radius + 1.0 - dist) * float64(col.A))
				img.SetNRGBA(x, y, color.NRGBA{col.R, col.G, col.B, alpha})
			}
		}
	}
	return walk.NewBitmapFromImage(img)
}

// ── app state ─────────────────────────────────────────────────────────────────

type seemaApp struct {
	form            *walk.MainWindow
	dotView         *walk.ImageView
	statusLabel     *walk.Label
	modeLabel       *walk.Label // adapter mode line (direct / bridge + iface)
	bmwLabel        *walk.Label // BMW ZGW discovery result
	disconnectLabel *walk.Label // last disconnect time

	client        *vpnclient.Client
	framer        bridge.Framer
	connectCtx    context.Context
	connectCancel context.CancelFunc
	refreshCh     chan struct{}

	lastDisconnect time.Time
	prevConnected  bool
}

func (a *seemaApp) setDot(kind dotKind) {
	if a.dotView == nil {
		return
	}
	if bmp, err := makeDotBitmap(dotColors[kind]); err == nil {
		_ = a.dotView.SetImage(bmp)
	}
}

func (a *seemaApp) connect() {
	cfg := config.ClientConfig{
		Server:    seemaServer,
		HubID:     seemaHubID,
		Login:     seemaLogin,
		Password:  seemaPassword,
		Transport: "auto",
		Mode:      "auto",
	}
	cfg.FEC = cfg.FEC.WithDefaults()
	cfg.UDP = cfg.UDP.WithDefaults()
	cfg.Bridge = cfg.Bridge.WithDefaults()

	go func() {
		iface, framer, adapterMode, err := clientadapter.OpenAdapter(cfg)
		if err != nil {
			log.Printf("seema: open adapter: %v", err)
			a.form.Synchronize(func() {
				_ = a.statusLabel.SetText("Error: " + err.Error())
				a.setDot(dotRed)
			})
			return
		}
		a.framer = framer

		ctx, cancel := context.WithCancel(context.Background())
		a.connectCtx = ctx
		a.connectCancel = cancel

		c := vpnclient.New(cfg, iface, framer, adapterMode)
		a.client = c

		a.refreshCh = make(chan struct{}, 1)
		c.OnChange(func() {
			select {
			case a.refreshCh <- struct{}{}:
			default:
			}
		})

		go a.refreshLoop(ctx)
		c.Start(ctx)
	}()
}

func (a *seemaApp) refreshLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.refreshCh:
			a.doRefresh()
		}
	}
}

func (a *seemaApp) doRefresh() {
	c := a.client
	if c == nil {
		return
	}
	stats := c.Stats()

	// Detect Connected → not-Connected transition and record disconnect time.
	nowConnected := stats.State == vpnclient.StateConnected
	if a.prevConnected && !nowConnected {
		a.lastDisconnect = time.Now()
	}
	a.prevConnected = nowConnected

	var text, modeText string
	var dot dotKind
	switch stats.State {
	case vpnclient.StateConnected:
		text = "Connected"
		dot = dotGreen
		if stats.AdapterMode != "" {
			modeText = stats.AdapterMode
		}
	case vpnclient.StateConnecting:
		text = "Connecting..."
		dot = dotYellow
	default:
		text = "Reconnecting..."
		if stats.LastError != "" {
			text += " (" + stats.LastError + ")"
		}
		dot = dotRed
	}

	a.form.Synchronize(func() {
		_ = a.statusLabel.SetText(text)
		_ = a.modeLabel.SetText(modeText)
		a.setDot(dot)
	})
}

// formatSeemaAgo returns "Last disconnect: Xm Ys ago" or "" when t is zero.
func formatSeemaAgo(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("Last disconnect: %dm %ds ago", m, s)
}

// ── run ──────────────────────────────────────────────────────────────────────

func run() {
	// Npcap is required for bridge-mode packet capture.
	// If it is not installed, launch the embedded wizard and then close so the
	// user can relaunch once installation is complete.
	if !pkgtun.NpcapInstalled() {
		walk.MsgBox(nil, "seema VPN — установка Npcap",
			"Npcap не установлен.\n\n"+
				"Сейчас откроется мастер установки Npcap.\n"+
				"После завершения установки запустите seema снова.",
			walk.MsgBoxIconInformation)
		if err := pkgtun.InstallNpcap(); err != nil {
			log.Printf("npcap install: %v", err)
		}
		return
	}

	a := &seemaApp{}

	if err := (MainWindow{
		AssignTo: &a.form,
		Title:    "seema",
		MinSize:  Size{Width: 360, Height: 130},
		Size:     Size{Width: 360, Height: 130},
		Layout:   VBox{Margins: Margins{Left: 16, Right: 16, Top: 12, Bottom: 12}, Spacing: 4},
		Children: []Widget{
			Composite{
				Layout: HBox{MarginsZero: true, Spacing: 10},
				Children: []Widget{
					ImageView{
						AssignTo: &a.dotView,
						MinSize:  Size{Width: 16, Height: 16},
						MaxSize:  Size{Width: 16, Height: 16},
					},
					Label{
						AssignTo: &a.statusLabel,
						Text:     "Connecting...",
						Font:     Font{Bold: true, PointSize: 11},
					},
				},
			},
			Label{
				AssignTo: &a.modeLabel,
				Text:     "",
				Font:     Font{PointSize: 9},
			},
			Label{
				AssignTo: &a.bmwLabel,
				Text:     "",
				Font:     Font{PointSize: 9},
			},
			Label{
				AssignTo: &a.disconnectLabel,
				Text:     "",
				Font:     Font{PointSize: 9},
			},
		},
	}.Create()); err != nil {
		walk.MsgBox(nil, "Error", err.Error(), walk.MsgBoxIconError)
		return
	}

	// Fix window to exactly 360×130: remove resize handle and maximise button.
	// We use Win32 directly instead of Walk's MaxSize to avoid the TTM_ADDTOOL
	// tooltip-registration failure that Walk triggers when MinSize==MaxSize on
	// the MainWindow (Walk changes window styles before the tooltip is ready).
	hwnd := a.form.Handle()
	style := win.GetWindowLong(hwnd, win.GWL_STYLE)
	win.SetWindowLong(hwnd, win.GWL_STYLE, style&^(win.WS_THICKFRAME|win.WS_MAXIMIZEBOX))

	// Set window icon from embedded resource.
	if ico, err := walk.NewIconFromResourceId(1); err == nil {
		_ = a.form.SetIcon(ico)
	}

	// Center on screen.
	sw := int(win.GetSystemMetrics(win.SM_CXSCREEN))
	sh := int(win.GetSystemMetrics(win.SM_CYSCREEN))
	b := a.form.BoundsPixels()
	x := (sw - b.Width) / 2
	y := (sh - b.Height) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	_ = a.form.SetBoundsPixels(walk.Rectangle{X: x, Y: y, Width: b.Width, Height: b.Height})

	a.setDot(dotYellow)

	// Disable Windows Firewall for the lifetime of the app; restore on exit.
	if err := winfirewall.Disable(); err != nil {
		log.Printf("winfirewall disable: %v", err)
	}
	a.form.Closing().Attach(func(_ *bool, _ walk.CloseReason) {
		_ = winfirewall.Enable()
	})

	// BMW ZGW discovery — runs independently of VPN connection state.
	go zgw.Run(context.Background(), func(info *zgw.Info) {
		text := zgw.FormatBMW(info)
		a.form.Synchronize(func() {
			if a.bmwLabel != nil {
				_ = a.bmwLabel.SetText(text)
			}
		})
	})

	// 1-second ticker to keep "last disconnect" counter current.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for range t.C {
			text := formatSeemaAgo(a.lastDisconnect)
			a.form.Synchronize(func() {
				if a.disconnectLabel != nil {
					_ = a.disconnectLabel.SetText(text)
				}
			})
		}
	}()

	// Start VPN immediately.
	a.form.Synchronize(a.connect)

	a.form.Run()
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	if !acquireSingleInstance() {
		return
	}
	ensureAdmin()

	if lf := openLogFile(); lf != nil {
		defer lf.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
	}

	defer func() {
		if r := recover(); r != nil {
			writeCrashReport(r)
		}
	}()

	update.CleanupOldFiles()
	go update.CheckAndUpdate(version, update.AssetForSeema(), update.DefaultMirrors())

	run()
}
