package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

func main() {
	a := app.NewWithID("com.atlanteg.supervpn")
	w := a.NewWindow("superVPN")
	w.SetMaster()
	ui := newMainUI(a, w)
	w.SetContent(ui.build())
	w.Resize(fyne.NewSize(540, 640))
	w.ShowAndRun()
}
