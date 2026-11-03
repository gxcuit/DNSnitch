// Package app implements the `check` use case shared by the CLI and the GUI:
// load the config, analyze it and classify load errors. It returns plain data
// and never renders text.
package app

import (
	"errors"
	"path/filepath"

	"dnsleak/internal/analyze"
	"dnsleak/internal/config"
	"dnsleak/internal/model"
)

// ErrorKind classifies why a config could not be analyzed.
type ErrorKind string

// Error kinds of CheckOutcome.ErrKind.
const (
	ErrNone      ErrorKind = ""
	ErrRead      ErrorKind = "read"      // file could not be read
	ErrParse     ErrorKind = "parse"     // invalid YAML / duplicate key / non-mapping root
	ErrEncrypted ErrorKind = "encrypted" // age-encrypted file
)

// CheckOutcome is the result of RunCheck.
type CheckOutcome struct {
	File     string          // config path as given
	Findings []model.Finding // sorted with analyze.SortFindings; nil on error
	ErrKind  ErrorKind       // ErrNone when the config was analyzed
	Err      error           // underlying error when ErrKind != ErrNone
}

// RunCheck loads and analyzes file. home is the mihomo home directory used to
// resolve rule-set caches and GeoSite.dat; when empty it defaults to the
// directory of file.
func RunCheck(file, home string) CheckOutcome {
	out := CheckOutcome{File: file}
	env, kind, err := LoadEnv(file, home)
	if err != nil {
		out.ErrKind, out.Err = kind, err
		return out
	}
	fs := env.Check()
	analyze.SortFindings(fs)
	out.Findings = fs
	return out
}

// LoadEnv loads file and builds the analysis environment (shared by check
// and trace). On failure it returns the error kind and the underlying error.
func LoadEnv(file, home string) (*analyze.Env, ErrorKind, error) {
	cfg, err := config.Load(file)
	if err != nil {
		var pe *config.ParseError
		switch {
		case errors.Is(err, config.ErrEncrypted):
			return nil, ErrEncrypted, err
		case errors.As(err, &pe):
			return nil, ErrParse, err
		default:
			return nil, ErrRead, err
		}
	}
	if home == "" {
		home = DefaultHome(file)
	}
	return analyze.NewEnv(cfg, home), ErrNone, nil
}

// DefaultHome returns the directory of file (made absolute when possible).
func DefaultHome(file string) string {
	abs, err := filepath.Abs(file)
	if err != nil {
		abs = file
	}
	return filepath.Dir(abs)
}

// EncryptedFinding is the CFG-02 finding reported for an age-encrypted file.
func EncryptedFinding(file string) model.Finding {
	return model.Finding{
		ID: "CFG-02", Severity: model.Error,
		Locations: []model.Location{{File: file, Role: model.RoleConfig}},
	}
}
