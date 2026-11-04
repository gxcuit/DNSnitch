//go:build !windows

package platform

import "runtime"

// collect reports only the OS: detection is not implemented here yet, so
// Decide marks both items unsupported. Linux / macOS support goes in
// inspect_linux.go / inspect_darwin.go.
func collect() Facts { return Facts{OS: runtime.GOOS} }
