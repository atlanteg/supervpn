//go:build !windows || (windows && fyne)

package main

import (
	"io"
	"log"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/atlanteg/supervpn/internal/update"
)

func main() {
	if lf := openLogFile(); lf != nil {
		defer lf.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
	}

	defer func() {
		if r := recover(); r != nil {
			writeCrashReport(r)
			panic(r)
		}
	}()

	a := app.NewWithID("com.atlanteg.supervpn")

	mirrors := loadSavedMirrors(a)
	// Use the Fyne-specific asset so Fyne builds update to Fyne builds,
	// not to the Win32/Walk variant.
	go update.CheckAndUpdate(version, update.AssetForClientGUIFyne(), mirrors)

	w := a.NewWindow("superVPN " + version + " by NBTboost creators © Atlanteg")
	w.SetMaster()
	ui := newMainUI(a, w)
	w.SetContent(ui.build())
	w.Resize(fyne.NewSize(540, 640))

	ui.initConfigSelect()

	w.ShowAndRun()
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
