package main

import (
	"bytes"
	"context"
	"crypto/sha256"
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

// saveDialog opens the native save dialog for SaveFix; tests replace it so
// that no window is needed. It returns "" when cancelled.
var saveDialog = runtime.SaveFileDialog

// GUIResult is the value returned by Check: either Result or Error is set.
type GUIResult struct {
	Result *report.CheckResult `json:"result,omitempty"`
	Error  *GUIError           `json:"error,omitempty"`
}

// GUIError describes why a config could not be analyzed, fixed or saved.
type GUIError struct {
	// Kind is an app.ErrorKind (read / parse / encrypted / verify /
	// same-file / exists / write / changed) or no-config / no-fix.
	Kind    string `json:"kind"`
	Message string `json:"message"` // display text from report.ErrorText
}

// GUIFixResult is the value returned by PlanFix: either Result (the fix
// preview, same struct as `dnsnitch fix --format json`) or Error is set.
type GUIFixResult struct {
	Result *report.FixResult `json:"result,omitempty"`
	Error  *GUIError         `json:"error,omitempty"`
}

// GUISaveResult is the value returned by SaveFix: exactly one of Path (the
// written file), Cancelled (the save dialog was cancelled) or Error is set.
type GUISaveResult struct {
	Path      string    `json:"path,omitempty"`
	Cancelled bool      `json:"cancelled,omitempty"`
	Error     *GUIError `json:"error,omitempty"`
}

// SourceFile is the content of a file shown in the source view. Lines have
// no line terminators; Lines[i] is line i+1.
type SourceFile struct {
	Path  string   `json:"path"`
	Lines []string `json:"lines"`
}

// App holds the methods bound to the frontend. Bound methods run
// concurrently: ctx is written once in startup (before the frontend can call
// anything); the other fields are guarded by mu, and allowed is replaced as
// a whole, never mutated, so a snapshot can be used without the lock.
type App struct {
	ctx context.Context

	mu      sync.Mutex
	seq     uint64   // number of Check calls started
	allowed []string // cleaned absolute files of the latest started Check
	config  string   // absolute config path of the latest started Check
	fixSeq  uint64   // number of PlanFix calls started
	// planned is the outcome of the latest PlanFix. Check and PlanFix clear
	// it when they start, and a PlanFix overtaken by either does not store
	// its outcome, so a stored plan always belongs to the latest Check.
	planned *app.FixOutcome
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
	a.config = path
	a.planned = nil // a fix preview belongs to the Check it was made for
	a.mu.Unlock()

	out := app.RunCheck(path, "")
	a.setAllowed(seq, out)

	if out.ErrKind != app.ErrNone {
		return GUIResult{Error: guiError(out.ErrKind, out.Err, path, "")}
	}
	r := report.BuildCheckResult(path, out.Findings)
	return GUIResult{Result: &r}
}

// guiError renders an app.ErrorKind of RunCheck, PlanFix or SaveFix; file
// is the config and dest the chosen output path (SaveFix).
func guiError(kind app.ErrorKind, err error, file, dest string) *GUIError {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	e := &GUIError{Kind: string(kind)}
	switch kind {
	case app.ErrEncrypted:
		e.Message = report.ErrorText(report.ErrKindEncrypted, "")
	case app.ErrParse:
		e.Message = report.ErrorText(report.ErrKindParse, detail)
	case app.ErrVerify:
		e.Message = report.ErrorText(report.ErrKindVerify, detail)
	case app.ErrSameFile:
		e.Message = report.ErrorText(report.ErrKindSameFile, dest)
	case app.ErrExists:
		e.Message = report.ErrorText(report.ErrKindExists, dest)
	case app.ErrWrite:
		e.Message = report.ErrorText(report.ErrKindWrite, detail)
	case app.ErrChanged:
		e.Message = report.ErrorText(report.ErrKindChanged, file)
	default:
		e.Message = report.ErrorText(report.ErrKindRead, detail)
	}
	return e
}

// textError is a GUIError of a kind that has no underlying error.
func textError(kind string) *GUIError {
	return &GUIError{Kind: kind, Message: report.ErrorText(kind, "")}
}

// PlanFix computes the automatic fixes of the config of the latest Check
// (app.PlanFix, same home as Check) without writing anything, and keeps the
// outcome for SaveFix. It takes no parameters: the frontend cannot choose
// the file, and the content to save is computed here.
func (a *App) PlanFix() GUIFixResult {
	a.mu.Lock()
	seq, file := a.seq, a.config
	a.fixSeq++
	fixSeq := a.fixSeq
	a.planned = nil
	a.mu.Unlock()
	if file == "" {
		return GUIFixResult{Error: textError(report.ErrKindNoConfig)}
	}

	out, kind, err := app.PlanFix(file, "")
	if kind != app.ErrNone {
		return GUIFixResult{Error: guiError(kind, err, file, "")}
	}
	a.mu.Lock()
	if seq == a.seq && fixSeq == a.fixSeq {
		a.planned = &out
	}
	a.mu.Unlock()
	r := report.BuildFixResult(out.File, out.Output, out.Plan, out.Before, out.After, false)
	return GUIFixResult{Result: &r}
}

// current returns the stored PlanFix outcome (nil when there is none).
func (a *App) current() *app.FixOutcome {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.planned
}

// SaveFix writes the fixed text of the latest PlanFix to a file chosen in
// the native save dialog (the only source of the path), defaulting to
// app.DefaultFixOutput next to the config. The dialog has already confirmed
// overwriting, so app.SaveFix runs with force; it still refuses the config
// itself (any alias) and a config changed since PlanFix (kind "changed").
func (a *App) SaveFix() GUISaveResult {
	p := a.current()
	if p == nil || p.Plan == nil || len(p.Plan.Edits) == 0 {
		return GUISaveResult{Error: textError(report.ErrKindNoFix)}
	}
	file := p.File
	// Refuse a config edited since the preview before asking for a path;
	// app.SaveFix checks again right before writing.
	data, err := os.ReadFile(file)
	if err != nil {
		return GUISaveResult{Error: guiError(app.ErrRead, err, file, "")}
	}
	if sha256.Sum256(data) != p.SourceHash {
		return GUISaveResult{Error: guiError(app.ErrChanged, nil, file, "")}
	}
	dest, err := saveDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultDirectory: filepath.Dir(file),
		DefaultFilename:  filepath.Base(app.DefaultFixOutput(file)),
		Title:            report.GUISaveDialogTitle,
		Filters: []runtime.FileFilter{
			{DisplayName: report.GUIFilterConfig, Pattern: "*.yaml;*.yml"},
			{DisplayName: report.GUIFilterAll, Pattern: "*.*"},
		},
		CanCreateDirectories: true,
	})
	if err != nil {
		return GUISaveResult{Error: guiError(app.ErrWrite, err, file, "")}
	}
	if dest == "" {
		return GUISaveResult{Cancelled: true}
	}
	// A Check or another PlanFix may have started while the dialog was open.
	if a.current() != p {
		return GUISaveResult{Error: textError(report.ErrKindNoFix)}
	}
	if abs, err := filepath.Abs(dest); err == nil {
		dest = abs
	}
	if kind, err := app.SaveFix(*p, dest, true); kind != app.ErrNone {
		return GUISaveResult{Error: guiError(kind, err, file, dest)}
	}
	return GUISaveResult{Path: dest}
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
