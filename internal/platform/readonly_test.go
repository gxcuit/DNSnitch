package platform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sourceFiles returns the non-test .go files of this package (all build
// tags, so the Windows collector is scanned on every OS).
func sourceFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		t.Fatal("no source files found")
	}
	return out
}

// TestReadOnly enforces R6.1: this package never writes the registry,
// executes programs or changes system settings (design §7). This is a
// coarse text scan; TestReadOnlyAST below is the precise check.
func TestReadOnly(t *testing.T) {
	forbidden := []string{
		"CreateKey", "SetDWordValue", "SetQWordValue", "SetStringValue", "SetBinaryValue",
		"SetExpandStringValue", "SetStringsValue", "DeleteKey", "DeleteValue",
		"registry.SET_VALUE", "registry.WRITE", "registry.ALL_ACCESS", "registry.CREATE_SUB_KEY",
		`"os/exec"`, "syscall.Exec", "ShellExecute", "CreateProcess", "StartProcess",
		"RegSetValue", "RegCreateKey", "RegDelete", "KEY_WRITE", "KEY_SET_VALUE", "KEY_ALL_ACCESS",
		"go:linkname", "LazyDLL", "LazySystemDLL", "LoadLibrary", "GetProcAddress",
	}
	for _, f := range sourceFiles(t) {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(data)
		for _, bad := range forbidden {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains forbidden %q", f, bad)
			}
		}
	}
}

// allowedImports lists every package this package may import. For the
// packages with OS access the members that may be used are listed too
// (nil = any member: the package has no side effects). Adding an entry
// requires checking that the API is read-only.
var allowedImports = map[string]map[string]bool{
	"errors":  nil,
	"runtime": nil,
	"strconv": nil,
	"strings": nil,
	"unsafe":  nil,
	"net":     {"ParseIP": true, "IP": true, "IPv4len": true, "IPv6len": true},
	"golang.org/x/sys/windows": {
		"GetAdaptersAddresses": true, "IpAdapterAddresses": true, "AF_UNSPEC": true,
		"GAA_FLAG_SKIP_ANYCAST": true, "GAA_FLAG_SKIP_MULTICAST": true, "GAA_FLAG_SKIP_DNS_SERVER": true,
		"ERROR_BUFFER_OVERFLOW": true, "IfOperStatusUp": true,
		"UTF16PtrToString": true, "BytePtrToString": true,
		"GetBestInterfaceEx": true, "SockaddrInet4": true, "SockaddrInet6": true,
	},
	"golang.org/x/sys/windows/registry": {
		"OpenKey": true, "Key": true, "LOCAL_MACHINE": true,
		"QUERY_VALUE": true, "ENUMERATE_SUB_KEYS": true, // the only access rights
		"DWORD": true, "ErrNotExist": true,
	},
}

const registryPath = "golang.org/x/sys/windows/registry"

// readOnlyAccess are the only access rights registry.OpenKey may receive.
var readOnlyAccess = map[string]bool{"QUERY_VALUE": true, "ENUMERATE_SUB_KEYS": true}

// writeLikeMethod matches method / function names that change state
// (registry.Key.SetDWordValue, DeleteKey, CreateKey, ...).
var writeLikeMethod = regexp.MustCompile(`^(Set|Create|Delete|Write|Save|Replace|Rename|Restore|Load|Exec|Start|Run|Kill)[A-Z_]?`)

// readOnlyViolations checks one parsed file: imports on the allow list,
// only allow-listed members of OS packages (aliases resolved), no
// write-like selector, and every registry.OpenKey call with an access mask
// built only from registry.QUERY_VALUE / ENUMERATE_SUB_KEYS (so numeric
// masks such as 0xF003F are rejected).
func readOnlyViolations(af *ast.File, src []byte) []string {
	var out []string
	if strings.Contains(string(src), "go:linkname") {
		out = append(out, "go:linkname directive")
	}
	local := map[string]string{} // local package name -> import path
	for _, imp := range af.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if _, ok := allowedImports[p]; !ok {
			out = append(out, "import "+p)
			continue
		}
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			if imp.Name.Name == "." || imp.Name.Name == "_" {
				out = append(out, "import "+imp.Name.Name+" "+p)
				continue
			}
			name = imp.Name.Name
		}
		local[name] = p
	}
	pkgOf := func(e ast.Expr) (string, string) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", ""
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Obj != nil { // id.Obj != nil: a local variable, not a package
			return "", ""
		}
		return local[id.Name], sel.Sel.Name
	}
	// readOnlyMask reports whether e is QUERY_VALUE / ENUMERATE_SUB_KEYS
	// joined with '|'.
	var readOnlyMask func(e ast.Expr) bool
	readOnlyMask = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.ParenExpr:
			return readOnlyMask(x.X)
		case *ast.BinaryExpr:
			return x.Op == token.OR && readOnlyMask(x.X) && readOnlyMask(x.Y)
		}
		p, name := pkgOf(e)
		return p == registryPath && readOnlyAccess[name]
	}

	openCalls := map[ast.Expr]bool{}
	ast.Inspect(af, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if p, name := pkgOf(call.Fun); p == registryPath && name == "OpenKey" {
			openCalls[call.Fun] = true
			if len(call.Args) != 3 || !readOnlyMask(call.Args[2]) {
				out = append(out, "registry.OpenKey with an access mask other than QUERY_VALUE | ENUMERATE_SUB_KEYS")
			}
		}
		return true
	})
	ast.Inspect(af, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if writeLikeMethod.MatchString(sel.Sel.Name) {
			out = append(out, "write-like call ."+sel.Sel.Name)
		}
		p, name := pkgOf(sel)
		if p == "" {
			return true
		}
		if members := allowedImports[p]; members != nil && !members[name] {
			out = append(out, p+"."+name+" is not on the read-only allow list")
		}
		if p == registryPath && name == "OpenKey" && !openCalls[sel] {
			out = append(out, "registry.OpenKey used as a value")
		}
		return true
	})
	return out
}

// TestReadOnlyAST applies readOnlyViolations to every source file.
func TestReadOnlyAST(t *testing.T) {
	fset := token.NewFileSet()
	seenOpen := false
	for _, f := range sourceFiles(t) {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range readOnlyViolations(af, src) {
			t.Errorf("%s: %s", f, v)
		}
		seenOpen = seenOpen || strings.Contains(string(src), "registry.OpenKey(")
	}
	if !seenOpen {
		t.Errorf("registry.OpenKey not found: is the scan looking at the right files?")
	}
}

// TestReadOnlyASTCatches makes sure the checker itself rejects the usual
// ways of writing the registry or running programs.
func TestReadOnlyASTCatches(t *testing.T) {
	const head = "package platform\nimport (\n\"golang.org/x/sys/windows\"\n\"golang.org/x/sys/windows/registry\"\n)\nvar _ = windows.AF_UNSPEC\n"
	bad := map[string]string{
		"numeric access mask": head + "func f() { registry.OpenKey(registry.LOCAL_MACHINE, `x`, 0xF003F) }",
		"ALL_ACCESS":          head + "func f() { registry.OpenKey(registry.LOCAL_MACHINE, `x`, registry.ALL_ACCESS) }",
		"mask via variable":   head + "func f() { m := registry.QUERY_VALUE; registry.OpenKey(registry.LOCAL_MACHINE, `x`, m) }",
		"mask with xor":       head + "func f() { registry.OpenKey(registry.LOCAL_MACHINE, `x`, registry.QUERY_VALUE^registry.ENUMERATE_SUB_KEYS) }",
		"OpenKey as value":    head + "var open = registry.OpenKey",
		"set value method":    head + "func f(k registry.Key) { k.SetDWordValue(`v`, 1) }",
		"create key":          head + "func f() { registry.CreateKey(registry.LOCAL_MACHINE, `x`, registry.QUERY_VALUE) }",
		"RegSetValueEx":       head + "func f() { windows.RegSetValueEx(0, nil, 0, 0, nil, 0) }",
		"CreateProcess":       head + "func f() { windows.CreateProcess(nil, nil, nil, nil, false, 0, nil, nil, nil, nil) }",
		"KEY_ALL_ACCESS":      head + "var _ = windows.KEY_ALL_ACCESS",
		"lazy dll":            head + "var _ = windows.NewLazySystemDLL(`advapi32.dll`)",
		"aliased windows":     "package platform\nimport w \"golang.org/x/sys/windows\"\nfunc f() { w.ShellExecute(0, nil, nil, nil, nil, 0) }",
		"aliased exec":        "package platform\nimport x \"os/exec\"\nvar _ = x.Command",
		"syscall":             "package platform\nimport \"syscall\"\nfunc f() { syscall.StartProcess(``, nil, nil) }",
		"os":                  "package platform\nimport \"os\"\nfunc f() { os.WriteFile(``, nil, 0) }",
		"dot import":          "package platform\nimport . \"golang.org/x/sys/windows\"\nvar _ = AF_UNSPEC",
		"linkname":            "package platform\nimport _ \"unsafe\"\n//go:linkname f x.y\nfunc f()",
	}
	for name, src := range bad {
		af, err := parser.ParseFile(token.NewFileSet(), name+".go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(readOnlyViolations(af, []byte(src))) == 0 {
			t.Errorf("%s: not detected", name)
		}
	}
	ok := head + "func f() { k, _ := registry.OpenKey(registry.LOCAL_MACHINE, `x`, registry.QUERY_VALUE|(registry.ENUMERATE_SUB_KEYS)); k.Close() }"
	af, err := parser.ParseFile(token.NewFileSet(), "ok.go", ok, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	if v := readOnlyViolations(af, []byte(ok)); len(v) != 0 {
		t.Errorf("read-only source rejected: %v", v)
	}
}

// TestRegistryAccessRights checks that every registry access-rights
// constant used is a read-only one.
func TestRegistryAccessRights(t *testing.T) {
	allowed := map[string]bool{
		"QUERY_VALUE": true, "ENUMERATE_SUB_KEYS": true, // access rights
		"LOCAL_MACHINE": true, "DWORD": true, // root key, value type
		"ErrNotExist": true, // error
	}
	re := regexp.MustCompile(`registry\.([A-Za-z_]+)`)
	seenOpen := false
	for _, f := range sourceFiles(t) {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			name := m[1]
			if name == "OpenKey" {
				seenOpen = true
				continue
			}
			if !allowed[name] {
				t.Errorf("%s uses registry.%s (not on the read-only allow list)", f, name)
			}
		}
	}
	if !seenOpen {
		t.Errorf("registry.OpenKey not found: is the scan looking at the right files?")
	}
}

// TestImports keeps the package self-contained: standard library and
// golang.org/x/sys only, no other internal package.
func TestImports(t *testing.T) {
	fset := token.NewFileSet()
	for _, f := range sourceFiles(t) {
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first := strings.SplitN(p, "/", 2)[0]
			if strings.HasPrefix(p, "golang.org/x/sys/") {
				continue
			}
			if strings.Contains(first, ".") || p == "dnsnitch" || strings.HasPrefix(p, "dnsnitch/") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}
