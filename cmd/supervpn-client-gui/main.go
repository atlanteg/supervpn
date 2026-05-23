//go:build !windows || (windows && fyne)

package main

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/driver/desktop"

	"github.com/atlanteg/supervpn/internal/update"
	"github.com/atlanteg/supervpn/internal/winfirewall"
)

func main() {
	if lf := openLogFile(); lf != nil {
		defer lf.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, lf, AppLog))
	} else {
		log.SetOutput(io.MultiWriter(os.Stderr, AppLog))
	}
	log.Printf("superVPN %s started", version)

	defer func() {
		if r := recover(); r != nil {
			writeCrashReport(r)
			panic(r)
		}
	}()

	a := app.NewWithID("com.atlanteg.supervpn")

	// Load application icon from icon.png next to the binary when present.
	if ico := loadAppIcon(); ico != nil {
		a.SetIcon(ico)
	}

	update.CleanupOldFiles()
	// Use the Fyne-specific asset so Fyne builds update to Fyne builds,
	// not to the Win32/Walk variant.
	go update.CheckAndUpdate(version, update.AssetForClientGUIFyne(), update.DefaultMirrors())

	w := a.NewWindow("superVPN " + version + " by NBTboost creators © Atlanteg")
	w.SetMaster()
	ui := newMainUI(a, w)
	w.SetContent(ui.build())
	w.Resize(fyne.NewSize(540, 640))

	// System tray support is only available when the Fyne driver implements
	// the desktop.App interface (i.e. on platforms with a desktop environment).
	if desk, ok := a.(desktop.App); ok {
		if ico := loadAppIcon(); ico != nil {
			desk.SetSystemTrayIcon(ico)
		}
		desk.SetSystemTrayMenu(fyne.NewMenu("superVPN",
			fyne.NewMenuItem("Show", func() {
				w.Show()
				w.RequestFocus()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit", a.Quit),
		))
	}

	// Intercept the close button: hide to tray when minimize_to_tray is set.
	w.SetCloseIntercept(func() {
		if ui.minimizeToTrayCheck != nil && ui.minimizeToTrayCheck.Checked {
			w.Hide()
		} else {
			a.Quit()
		}
	})

	ui.initConfigSelect()

	if ui.autoConnectCheck != nil && ui.autoConnectCheck.Checked {
		go ui.onConnect()
	}

	// Disable Windows Firewall for the lifetime of the app (no-op on macOS/Linux).
	if err := winfirewall.Disable(); err != nil {
		log.Printf("winfirewall disable: %v", err)
	}
	defer winfirewall.Enable()

	w.ShowAndRun()
}

// loadAppIcon reads icon.png from the same directory as the executable and
// returns it as a Fyne resource.  Returns nil when the file is not present —
// Fyne falls back to its built-in logo silently in that case.
func loadAppIcon() fyne.Resource {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "icon.png"))
	if err != nil {
		return nil
	}
	return fyne.NewStaticResource("icon.png", data)
}

// loadSavedMirrors returns update mirror URLs derived from the last server
// address saved in Fyne preferences.
func loadSavedMirrors(a fyne.App) []string {
	server := a.Preferences().String("last_server")
	if server == "" {
		return nil
	}
	i := len(server) - 1
	for i >= 0 && server[i] != ':' {
		i--
	}
	host := server
	if i > 0 {
		host = server[:i]
	}
	if host == "" {
		return nil
	}
	return []string{"http://" + host + "/update"}
}
