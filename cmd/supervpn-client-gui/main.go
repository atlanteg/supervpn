package main

import (
	"github.com/atlanteg/supervpn/internal/update"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

var version = "dev"

func main() {
	a := app.NewWithID("com.atlanteg.supervpn")

	// Check for updates in the background; mirrors are populated later from the
	// last-used server preference stored by the UI.
	mirrors := loadSavedMirrors(a)
	go update.CheckAndUpdate(version, update.AssetForClientGUI(), mirrors)

	w := a.NewWindow("superVPN")
	w.SetMaster()
	ui := newMainUI(a, w)
	w.SetContent(ui.build())
	w.Resize(fyne.NewSize(540, 640))
	w.ShowAndRun()
}

// loadSavedMirrors returns update mirror URLs derived from the last server
// address saved in Fyne preferences, mirroring the CLI auto-derive logic.
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
