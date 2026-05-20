//go:build ignore

// gen_icon generates a simple 256×256 green circle as icon.png next to this
// file.  It is used by CI as a placeholder when the user has not yet committed
// a real icon.  Run with:
//
//	go run cmd/supervpn-client-gui/gen_icon.go
//
// Replace cmd/supervpn-client-gui/icon.png with any PNG and CI will embed it
// automatically via go-winres.
package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"runtime"
)

func main() {
	_, file, _, _ := runtime.Caller(0)
	out := filepath.Join(filepath.Dir(file), "icon.png")

	const size = 256
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	cx, cy := float64(size-1)/2, float64(size-1)/2
	radius := cx - 6

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			d := math.Sqrt(dx*dx + dy*dy)
			if d <= radius {
				img.SetNRGBA(x, y, color.NRGBA{R: 60, G: 185, B: 80, A: 255})
			} else if d <= radius+3 {
				a := uint8((radius + 3 - d) / 3 * 255)
				img.SetNRGBA(x, y, color.NRGBA{R: 60, G: 185, B: 80, A: a})
			}
		}
	}

	f, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		panic(err)
	}
}
