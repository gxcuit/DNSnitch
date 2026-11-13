package app

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"dnsnitch/internal/analyze"
	"dnsnitch/internal/config"
	"dnsnitch/internal/fix"
	"dnsnitch/internal/model"
)

// FixOutcome is the result of PlanFix.
type FixOutcome struct {
	File       string          // config path as given
	Output     string          // default output path (DefaultFixOutput)
	Plan       *fix.Plan       // nil when the config could not be analyzed
	Before     []model.Finding // findings of the config, sorted
	After      []model.Finding // findings of the fixed text, sorted (= Before without edits)
	SourceHash [32]byte        // sha256 of the config bytes the plan was made from
}

// PlanFix reads file, computes the automatic fixes and checks the result
// with the same home as RunCheck. Nothing is written. Load errors use the
// RunCheck kinds; a fixed text that does not load or has an error finding
// the config did not have yields ErrVerify (the outcome is still returned).
func PlanFix(file, home string) (FixOutcome, ErrorKind, error) {
	return planFix(file, home, newChecker)
}

// newChecker returns the check used for planning and verification:
// config.Parse + analyze, the same as RunCheck.
func newChecker(file, home string) fix.CheckFunc {
	return func(data []byte) ([]model.Finding, error) {
		cfg, err := config.Parse(file, data)
		if err != nil {
			return nil, err
		}
		fs := analyze.NewEnv(cfg, home).Check()
		analyze.SortFindings(fs)
		return fs, nil
	}
}

// planFix is PlanFix with an injectable checker (tests force verification
// failures with it).
func planFix(file, home string, mk func(file, home string) fix.CheckFunc) (FixOutcome, ErrorKind, error) {
	out := FixOutcome{File: file, Output: DefaultFixOutput(file)}
	data, err := os.ReadFile(file)
	if err != nil {
		return out, ErrRead, err
	}
	out.SourceHash = sha256.Sum256(data)
	if home == "" {
		home = DefaultHome(file)
	}
	check := mk(file, home)
	before, err := check(data)
	if err != nil {
		return out, loadErrKind(err), err
	}
	out.Before = before
	plan, err := fix.Build(file, data, check)
	if err != nil {
		return out, ErrVerify, err
	}
	out.Plan = plan
	if len(plan.Edits) == 0 {
		out.After = before
		return out, ErrNone, nil
	}
	after, err := check(plan.Fixed)
	if err != nil {
		return out, ErrVerify, fmt.Errorf("fixed config does not load: %w", err)
	}
	out.After = after
	if f, ok := fix.NewError(before, after); ok {
		return out, ErrVerify, fmt.Errorf("fixed config has a new %s finding", f.ID)
	}
	return out, ErrNone, nil
}

// DefaultFixOutput returns the default output path next to file:
// config.yaml -> config.fixed.yaml, config.yml -> config.fixed.yml,
// config -> config.fixed.yaml.
func DefaultFixOutput(file string) string {
	ext := filepath.Ext(file)
	if ext == "" {
		return file + ".fixed.yaml"
	}
	return strings.TrimSuffix(file, ext) + ".fixed" + ext
}

// rename is os.Rename; tests replace it to simulate write failures.
var rename = os.Rename

// SaveFix writes the fixed text of out to dest (never to the config
// itself). It writes nothing when the plan has no edits. dest must not be
// the config (any alias, judged by os.SameFile), must not exist unless
// force is set, and the config must still have the bytes the plan was made
// from. The file is written to a temporary file in dest's directory, synced
// and renamed over dest.
func SaveFix(out FixOutcome, dest string, force bool) (ErrorKind, error) {
	if out.Plan == nil || len(out.Plan.Edits) == 0 {
		return ErrNone, nil
	}
	srcInfo, err := os.Stat(out.File)
	if err != nil {
		return ErrRead, err
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return ErrWrite, err
	}
	switch info, err := os.Stat(abs); {
	case err == nil:
		if os.SameFile(srcInfo, info) {
			return ErrSameFile, fmt.Errorf("output %s is the config file itself", dest)
		}
		if info.IsDir() {
			// Not "exists": --force could not help.
			return ErrWrite, fmt.Errorf("output %s is a directory", dest)
		}
		if !force {
			return ErrExists, fmt.Errorf("output %s already exists", dest)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return ErrWrite, err
	}
	data, err := os.ReadFile(out.File)
	if err != nil {
		return ErrRead, err
	}
	if sha256.Sum256(data) != out.SourceHash {
		return ErrChanged, fmt.Errorf("config %s changed after the fix was planned", out.File)
	}
	if err := writeAtomic(abs, out.Plan.Fixed, srcInfo.Mode().Perm()|0o200); err != nil {
		return ErrWrite, err
	}
	return ErrNone, nil
}

// writeAtomic writes data to a temporary file next to dest and renames it
// over dest; the temporary file is removed on any failure.
func writeAtomic(dest string, data []byte, perm os.FileMode) (err error) {
	f, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".*.tmp")
	if err != nil {
		return err
	}
	tmp, closed := f.Name(), false
	defer func() {
		if err != nil {
			if !closed {
				f.Close()
			}
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	closed = true
	if err = f.Close(); err != nil {
		return err
	}
	return rename(tmp, dest)
}
