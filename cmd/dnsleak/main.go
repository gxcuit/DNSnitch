// Command dnsleak statically checks a mihomo config for DNS leaks.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"dnsleak/internal/analyze"
	"dnsleak/internal/config"
	"dnsleak/internal/model"
	"dnsleak/internal/report"
	"dnsleak/internal/trace"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	format string
	home   string
	args   []string
}

// parseArgs parses flags that may appear before or after positional
// arguments.
func parseArgs(args []string) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("dnsleak", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.format, "format", report.FormatText, "")
	fs.StringVar(&o.home, "home", "", "")
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		o.args = append(o.args, args[0])
		args = args[1:]
	}
	if o.format != report.FormatText && o.format != report.FormatJSON {
		return nil, &formatError{o.format}
	}
	return o, nil
}

type formatError struct{ format string }

func (e *formatError) Error() string { return e.format }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, report.UsageText())
		return 2
	}
	cmd := args[0]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Fprint(stdout, report.UsageText())
		return 0
	}
	o, err := parseArgs(args[1:])
	if err != nil {
		var fe *formatError
		if errors.As(err, &fe) {
			fmt.Fprintln(stderr, report.ErrorText(report.ErrKindFormat, fe.format))
		} else {
			fmt.Fprintln(stderr, report.ErrorText(report.ErrKindArgs, err.Error()))
		}
		return 2
	}

	switch {
	case cmd == "check" && len(o.args) == 1:
	case cmd == "trace" && len(o.args) == 2 && strings.Trim(strings.TrimSpace(o.args[1]), ".") != "":
	default:
		fmt.Fprintln(stderr, report.ErrorText(report.ErrKindArgs, ""))
		return 2
	}
	file := o.args[0]

	cfg, err := config.Load(file)
	if err != nil {
		switch {
		case errors.Is(err, config.ErrEncrypted):
			f := model.Finding{
				ID: "CFG-02", Severity: model.Error,
				Locations: []model.Location{{File: file, Role: model.RoleConfig}},
			}
			_ = report.WriteCheck(stdout, o.format, file, []model.Finding{f})
		case isParseError(err):
			fmt.Fprintln(stderr, report.ErrorText(report.ErrKindParse, err.Error()))
		default:
			fmt.Fprintln(stderr, report.ErrorText(report.ErrKindRead, err.Error()))
		}
		return 2
	}

	home := o.home
	if home == "" {
		abs, err := filepath.Abs(file)
		if err != nil {
			abs = file
		}
		home = filepath.Dir(abs)
	}
	env := analyze.NewEnv(cfg, home)

	if cmd == "check" {
		fs := env.Check()
		if err := report.WriteCheck(stdout, o.format, file, fs); err != nil {
			return 2
		}
		return report.ExitCode(fs)
	}

	res := trace.Run(env, o.args[1])
	if err := report.WriteTrace(stdout, o.format, file, res); err != nil {
		return 2
	}
	return report.TraceExitCode(res)
}

func isParseError(err error) bool {
	var pe *config.ParseError
	return errors.As(err, &pe)
}
