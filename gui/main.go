// Command dnsnitch-gui is the desktop window of dnsnitch (Wails v2).
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"dnsnitch/internal/report"
)

// assets is the built frontend. frontend/dist/.gitkeep is committed (and
// re-created by every vite build from frontend/public/.gitkeep) so that this
// embed compiles, and `go vet` / `go test` work, before the frontend is built.
//
//go:embed all:frontend/dist
var assets embed.FS

func main() {
	a := NewApp()
	err := wails.Run(&options.App{
		Title:     report.GUIWindowTitle,
		Width:     1200,
		Height:    800,
		MinWidth:  800,
		MinHeight: 500,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup: a.startup,
		Bind:      []interface{}{a},
		// The frontend registers the drop listener with the JS runtime's
		// OnFileDrop and receives absolute paths. DisableWebViewDrop must stay
		// false: it turns off WebView2 external drops, so no drop would arrive.
		DragAndDrop: &options.DragAndDrop{EnableFileDrop: true},
		Windows: &windows.Options{
			Theme: windows.SystemDefault,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
