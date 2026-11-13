// Command dnsnitch statically checks a mihomo config for DNS leaks.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"dnsnitch/internal/app"
	"dnsnitch/internal/model"
	"dnsnitch/internal/platform"
	"dnsnitch/internal/report"
	"dnsnitch/internal/trace"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// inspectSystem reads the system status for `status`; tests replace it.
var inspectSystem = platform.Inspect

// planFix plans the fixes for `fix`; tests replace it to force failures.
var planFix = app.PlanFix

type options struct {
	format  string
	home    string
	homeSet bool // --home given, even with an empty value
	args    []string

	// fix only
	output  string
	force   bool
	dryRun  bool
	fixFlag bool // any of -o / --output / --force / --dry-run given
}

// parseArgs parses flags that may appear before or after positional
// arguments.
func parseArgs(args []string) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("dnsnitch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.format, "format", report.FormatText, "")
	fs.StringVar(&o.home, "home", "", "")
	fs.StringVar(&o.output, "o", "", "")
	fs.StringVar(&o.output, "output", "", "")
	fs.BoolVar(&o.force, "force", false, "")
	fs.BoolVar(&o.dryRun, "dry-run", false, "")
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
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "home":
			o.homeSet = true
		case "o", "output", "force", "dry-run":
			o.fixFlag = true
		}
	})
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

	if o.fixFlag && cmd != "fix" {
		fmt.Fprintln(stderr, report.ErrorText(report.ErrKindArgs, report.ArgFixOnly))
		return 2
	}

	if cmd == "status" {
		if len(o.args) != 0 || o.homeSet {
			fmt.Fprintln(stderr, report.ErrorText(report.ErrKindArgs, ""))
			return 2
		}
		v := report.BuildStatusView(inspectSystem())
		if err := report.WriteStatus(stdout, o.format, v); err != nil {
			return 2
		}
		return report.StatusExitCode(v)
	}

	switch {
	case (cmd == "check" || cmd == "fix") && len(o.args) == 1:
	case cmd == "trace" && len(o.args) == 2 && strings.Trim(strings.TrimSpace(o.args[1]), ".") != "":
	default:
		fmt.Fprintln(stderr, report.ErrorText(report.ErrKindArgs, ""))
		return 2
	}
	file := o.args[0]

	if cmd == "fix" {
		return runFix(o, file, stdout, stderr)
	}

	if cmd == "check" {
		out := app.RunCheck(file, o.home)
		if code, failed := reportLoadError(stdout, stderr, o.format, file, out.ErrKind, out.Err); failed {
			return code
		}
		if err := report.WriteCheck(stdout, o.format, file, out.Findings); err != nil {
			return 2
		}
		return report.ExitCode(out.Findings)
	}

	env, kind, err := app.LoadEnv(file, o.home)
	if code, failed := reportLoadError(stdout, stderr, o.format, file, kind, err); failed {
		return code
	}
	res := trace.Run(env, o.args[1])
	if err := report.WriteTrace(stdout, o.format, file, res); err != nil {
		return 2
	}
	return report.TraceExitCode(res)
}

// runFix plans the fixes of file, writes the fixed config to a new file
// (unless --dry-run or nothing changed) and reports. The exit code follows
// the findings of the fixed config; any failure exits 2.
func runFix(o *options, file string, stdout, stderr io.Writer) int {
	out, kind, err := planFix(file, o.home)
	switch kind {
	case app.ErrNone:
	case app.ErrVerify:
		fmt.Fprintln(stderr, report.ErrorText(report.ErrKindVerify, err.Error()))
		return 2
	default:
		code, _ := reportLoadError(stdout, stderr, o.format, file, kind, err)
		return code
	}
	dest := o.output
	if dest == "" {
		dest = out.Output
	}
	written := false
	if !o.dryRun && out.Plan != nil && len(out.Plan.Edits) > 0 {
		if kind, err := app.SaveFix(out, dest, o.force); kind != app.ErrNone {
			fmt.Fprintln(stderr, saveErrorText(kind, err, file, dest))
			return 2
		}
		written = true
	}
	r := report.BuildFixResult(file, dest, out.Plan, out.Before, out.After, written)
	if err := report.WriteFix(stdout, o.format, r); err != nil {
		return 2
	}
	return report.ExitCode(out.After)
}

// saveErrorText renders an app.SaveFix failure.
func saveErrorText(kind app.ErrorKind, err error, file, dest string) string {
	switch kind {
	case app.ErrSameFile:
		return report.ErrorText(report.ErrKindSameFile, dest)
	case app.ErrExists:
		return report.ErrorText(report.ErrKindExists, dest)
	case app.ErrChanged:
		return report.ErrorText(report.ErrKindChanged, file)
	case app.ErrWrite:
		return report.ErrorText(report.ErrKindWrite, err.Error())
	default:
		return report.ErrorText(report.ErrKindRead, err.Error())
	}
}

// reportLoadError prints a config load failure and returns exit code 2 with
// failed = true; it returns failed = false when kind is app.ErrNone.
func reportLoadError(stdout, stderr io.Writer, format, file string, kind app.ErrorKind, err error) (int, bool) {
	switch kind {
	case app.ErrNone:
		return 0, false
	case app.ErrEncrypted:
		_ = report.WriteCheck(stdout, format, file, []model.Finding{app.EncryptedFinding(file)})
	case app.ErrParse:
		fmt.Fprintln(stderr, report.ErrorText(report.ErrKindParse, err.Error()))
	default:
		fmt.Fprintln(stderr, report.ErrorText(report.ErrKindRead, err.Error()))
	}
	return 2, true
}
