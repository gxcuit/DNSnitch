package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"dnsnitch/internal/app"
	"dnsnitch/internal/platform"
	"dnsnitch/internal/report"
)

// maxSourceSize caps the size of a file shown in the source view.
const maxSourceSize = 32 << 20

// inspectSystem reads the system status for SystemStatus; tests replace it.
var inspectSystem = platform.Inspect

// GUIResult is the value returned by Check: either Result or Error is set.
type GUIResult struct {
	Result *report.CheckResult `json:"result,omitempty"`
	Error  *GUIError           `json:"error,omitempty"`
}

// GUIError describes why a config could not be analyzed.
type GUIError struct {
	Kind    string `json:"kind"`    // read / parse / encrypted
	Message string `json:"message"` // display text from report.ErrorText
}

// SourceFile is the content of a file shown in the source view. Lines have
// no line terminators; Lines[i] is line i+1.
type SourceFile struct {
	Path  string   `json:"path"`
	Lines []string `json:"lines"`
}

// App holds the methods bound to the frontend. Bound methods run
// concurrently: ctx is written once in startup (before the frontend can call
// anything); seq and allowed are guarded by mu, and allowed is replaced as a
// whole, never mutated, so a snapshot can be used without the lock.
type App struct {
	ctx context.Context

	mu      sync.Mutex
	seq     uint64   // number of Check calls started
	allowed []string // cleaned absolute files of the latest started Check
}

// NewApp creates the bound App.
func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// ChooseFile opens the native file dialog. It returns "" when cancelled.
func (a *App) ChooseFile() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: report.GUIDialogTitle,
		Filters: []runtime.FileFilter{
			{DisplayName: report.GUIFilterConfig, Pattern: "*.yaml;*.yml"},
			{DisplayName: report.GUIFilterAll, Pattern: "*.*"},
		},
	})
}

// Labels returns the display names of severities, location roles and
// resolver levels / sources used in a CheckResult.
func (a *App) Labels() report.Labels { return report.GUILabels() }

// SystemStatus inspects TUN mode and smart multi-homed name resolution
// (read-only) and renders them with report.BuildStatusView, the same
// function as `dnsnitch status --format json`. It is independent of Check.
func (a *App) SystemStatus() report.StatusView {
	return report.BuildStatusView(inspectSystem())
}

// Check analyzes the config at path (made absolute first). The findings are
// built by report.BuildCheckResult, the same function as `dnsnitch check
// --format json`, so their order and text match the CLI.
func (a *App) Check(path string) GUIResult {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	a.mu.Lock()
	a.seq++
	seq := a.seq
	a.mu.Unlock()

	out := app.RunCheck(path, "")
	a.setAllowed(seq, out)

	if out.ErrKind != app.ErrNone {
		return GUIResult{Error: guiError(out)}
	}
	r := report.BuildCheckResult(path, out.Findings)
	return GUIResult{Result: &r}
}

func guiError(out app.CheckOutcome) *GUIError {
	e := &GUIError{Kind: string(out.ErrKind)}
	switch out.ErrKind {
	case app.ErrEncrypted:
		e.Message = report.ErrorText(report.ErrKindEncrypted, "")
	case app.ErrParse:
		e.Message = report.ErrorText(report.ErrKindParse, out.Err.Error())
	default:
		e.Message = report.ErrorText(report.ErrKindRead, out.Err.Error())
	}
	return e
}

// setAllowed records the files of a Check: the config itself and every file
// referenced by a finding location. Results of a Check that was overtaken by
// a later one are ignored.
func (a *App) setAllowed(seq uint64, out app.CheckOutcome) {
	paths := []string{out.File}
	for _, f := range out.Findings {
		for _, l := range f.Locations {
			if l.File != "" && filepath.IsAbs(l.File) {
				paths = append(paths, l.File)
			}
		}
	}
	var list []string
	seen := map[string]bool{}
	for _, p := range paths {
		p = filepath.Clean(p)
		k := pathKey(p)
		if seen[k] {
			continue
		}
		seen[k] = true
		list = append(list, p)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if seq == a.seq {
		a.allowed = list
	}
}

// pathKey normalizes a cleaned absolute path for comparison. Windows paths
// are case-insensitive.
func pathKey(p string) string {
	if goruntime.GOOS == "windows" {
		return strings.ToLower(p)
	}
	return p
}

// hasStreamSyntax reports whether a Windows path names an NTFS alternate
// data stream ("file:stream", "file::$DATA"). Such a path has the file
// identity of the file it belongs to but different content.
func hasStreamSyntax(p string) bool {
	if goruntime.GOOS != "windows" {
		return false
	}
	return strings.Contains(p[len(filepath.VolumeName(p)):], ":")
}

// errSourceTooLarge is reported for files above maxSourceSize.
var errSourceTooLarge = errors.New("file too large")

// errNotAllowed is the error for any path outside the whitelist; it does
// not reveal whether the path exists.
func errNotAllowed() error { return errors.New(report.ErrorText(report.ErrKindSource, "")) }

// openAllowed opens path (absolute, cleaned) if it is one of the allowed
// files. The decision is made on the opened handle by file identity (as
// os.SameFile), so aliases of an allowed file (case, 8.3 short names,
// junctions, symlinks) are accepted, while a path that names another file -
// or is swapped to another file between the check and the read - is not.
func (a *App) openAllowed(path string) (*os.File, error) {
	a.mu.Lock()
	list := a.allowed
	a.mu.Unlock()

	listed := false
	k := pathKey(path)
	for _, p := range list {
		if pathKey(p) == k {
			listed = true
			break
		}
	}

	f, err := os.Open(path)
	if err != nil {
		if listed {
			return nil, errors.New(report.ErrorText(report.ErrKindSourceRead, err.Error()))
		}
		return nil, errNotAllowed()
	}
	if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
		for _, p := range list {
			if ai, err := os.Stat(p); err == nil && os.SameFile(ai, info) {
				return f, nil
			}
		}
	}
	f.Close()
	return nil, errNotAllowed()
}

// ReadSource returns the lines of path for the source view. Only the config
// of the latest Check and the files referenced by its findings may be read;
// relative paths are refused. "\r" is removed from the content.
func (a *App) ReadSource(path string) (SourceFile, error) {
	if path == "" || !filepath.IsAbs(path) || hasStreamSyntax(path) {
		return SourceFile{}, errNotAllowed()
	}
	f, err := a.openAllowed(filepath.Clean(path))
	if err != nil {
		return SourceFile{}, err
	}
	defer f.Close()
	data, err := readLimited(f, maxSourceSize)
	if err != nil {
		return SourceFile{}, errors.New(report.ErrorText(report.ErrKindSourceRead, err.Error()))
	}
	if isBinary(data) {
		return SourceFile{}, errors.New(report.ErrorText(report.ErrKindSourceBinary, ""))
	}
	text := strings.ReplaceAll(string(data), "\r", "")
	text = strings.TrimSuffix(text, "\n")
	lines := []string{}
	if text != "" {
		lines = strings.Split(text, "\n")
	}
	return SourceFile{Path: path, Lines: lines}, nil
}

// readLimited reads r, failing with errSourceTooLarge above limit bytes.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errSourceTooLarge
	}
	return data, nil
}

// isBinary reports whether data looks like a binary file (NUL byte in the
// first 8 KiB), e.g. .mrs rule-sets or GeoSite.dat.
func isBinary(data []byte) bool {
	if len(data) > 8192 {
		data = data[:8192]
	}
	return bytes.IndexByte(data, 0) >= 0
}
