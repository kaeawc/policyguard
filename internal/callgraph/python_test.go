package callgraph

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaeawc/policyguard/internal/scanner"
)

func loadPythonDir(t *testing.T, root string) []*scanner.File {
	t.Helper()
	var files []*scanner.File
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".py") {
			return nil
		}
		f, perr := scanner.ParseFile(context.Background(), path, scanner.LangPython)
		if perr != nil {
			return perr
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return files
}

func TestBuildPython_BasicReachability(t *testing.T) {
	root := "../../tests/fixtures/python/callgraph_basic"
	files := loadPythonDir(t, root)
	if len(files) == 0 {
		t.Fatalf("no fixture files found under %s", root)
	}

	g := BuildPython(files, root)

	wantFuncs := []FQN{
		"app.handlers.fetch_user_summary",
		"app.handlers.load_user",
		"app.redactor.redact",
	}
	for _, w := range wantFuncs {
		if _, ok := g.Funcs[w]; !ok {
			t.Errorf("missing function %q in graph; have %v", w, keys(g.Funcs))
		}
	}

	calls := g.Calls["app.handlers.fetch_user_summary"]
	if len(calls) == 0 {
		t.Fatalf("expected calls under fetch_user_summary, got none")
	}
	wantCallees := map[FQN]bool{
		"app.handlers.load_user":    false,
		"app.redactor.redact":       false,
		"anthropic.messages.create": false,
	}
	for _, c := range calls {
		if _, ok := wantCallees[c.Callee]; ok {
			wantCallees[c.Callee] = true
		}
	}
	for callee, seen := range wantCallees {
		if !seen {
			t.Errorf("expected callee %q under fetch_user_summary; calls=%v", callee, calls)
		}
	}
}

func TestBuildPython_ExtractsDecorators(t *testing.T) {
	src := []byte(`@redacted
def safe_log(x):
    pass

@auth.required
@cache(maxsize=10)
def get_user(uid):
    return {}

def plain():
    return 1
`)
	f, err := scanner.ParseBytes(context.Background(), "x.py", scanner.LangPython, src)
	if err != nil {
		t.Fatal(err)
	}
	g := BuildPython([]*scanner.File{f}, "")
	cases := map[FQN][]string{
		"x.safe_log": {"redacted"},
		"x.get_user": {"auth.required", "cache"}, // call-form decorator collapses to its callee name
		"x.plain":    nil,
	}
	for fqn, want := range cases {
		fn, ok := g.Funcs[fqn]
		if !ok {
			t.Fatalf("missing function %q", fqn)
		}
		if !equalStrSlice(fn.Decorators, want) {
			t.Errorf("Decorators[%q] = %v, want %v", fqn, fn.Decorators, want)
		}
	}
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBuildPython_ExtractsFieldAccess(t *testing.T) {
	src := []byte(`def f(user):
    e = user.email          # read — should be captured
    user.method()           # call — NOT a field-access site
    log(user.profile.name)  # nested read inside call args
`)
	file, err := scanner.ParseBytes(context.Background(), "x.py", scanner.LangPython, src)
	if err != nil {
		t.Fatal(err)
	}
	g := BuildPython([]*scanner.File{file}, "")

	const fn FQN = "x.f"
	fields := g.Fields[fn]
	if len(fields) == 0 {
		t.Fatalf("no field accesses captured")
	}

	wantFields := map[string]bool{"email": false, "name": false, "profile": false}
	for _, f := range fields {
		if _, ok := wantFields[f.Field]; ok {
			wantFields[f.Field] = true
		}
		if f.Field == "method" {
			t.Errorf("call function %q should not appear as field access", f.Path)
		}
	}
	for k, seen := range wantFields {
		if !seen {
			t.Errorf("missing expected field %q in %+v", k, fields)
		}
	}
}

func TestBuildPython_RecordsSuppressions(t *testing.T) {
	src := []byte(`def f():
    # policyguard: ignore foo, bar
    return 1
# policyguard: ignore-all
def g():
    return 2
`)
	file, err := scanner.ParseBytes(context.Background(), "x.py", scanner.LangPython, src)
	if err != nil {
		t.Fatal(err)
	}
	g := BuildPython([]*scanner.File{file}, "")
	supps := g.Suppressions["x.py"]
	if len(supps) != 2 {
		t.Fatalf("Suppressions = %+v, want 2", supps)
	}
	if supps[0].Line != 2 || len(supps[0].PolicyIDs) != 2 {
		t.Errorf("first suppression = %+v", supps[0])
	}
	if supps[1].Line != 4 || supps[1].PolicyIDs[0] != "*" {
		t.Errorf("second suppression = %+v", supps[1])
	}
}

func TestBuildPython_RelativeImports(t *testing.T) {
	// app/handlers.py imports siblings via `.` and a parent-level
	// module via `..`.
	src := []byte(`from . import users
from .helpers import sanitize
from ..lib import shared

def f():
    return users.get(1)

def g():
    return sanitize("x")

def h():
    return shared.load()
`)
	file, err := scanner.ParseBytes(context.Background(), "app/handlers.py", scanner.LangPython, src)
	if err != nil {
		t.Fatal(err)
	}
	g := BuildPython([]*scanner.File{file}, "")

	want := map[FQN]FQN{
		"app.handlers.f": "app.users.get",
		"app.handlers.g": "app.helpers.sanitize",
		"app.handlers.h": "lib.shared.load",
	}
	for caller, wantCallee := range want {
		calls := g.Calls[caller]
		if len(calls) != 1 {
			t.Errorf("%s: got %+v", caller, calls)
			continue
		}
		if calls[0].Callee != wantCallee {
			t.Errorf("%s callee = %q, want %q", caller, calls[0].Callee, wantCallee)
		}
	}
}

func TestBuildPython_RelativeImportFromInit(t *testing.T) {
	// In an __init__.py, modFQN == package FQN; `.foo` resolves to
	// `<package>.foo`.
	src := []byte(`from . import sibling

def f():
    return sibling.run()
`)
	file, err := scanner.ParseBytes(context.Background(), "app/__init__.py", scanner.LangPython, src)
	if err != nil {
		t.Fatal(err)
	}
	g := BuildPython([]*scanner.File{file}, "")
	calls := g.Calls["app.f"]
	if len(calls) != 1 || calls[0].Callee != "app.sibling.run" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestPythonRelativeBase(t *testing.T) {
	tests := []struct {
		pkg    FQN
		dots   int
		want   FQN
		wantOK bool
	}{
		{"app", 1, "app", true},
		{"app.handlers", 1, "app.handlers", true},
		{"app.handlers", 2, "app", true},
		{"app.handlers", 3, "", true},  // climbs to root
		{"app.handlers", 4, "", false}, // climbs past root
		{"a.b.c", 2, "a.b", true},
		{"a.b.c", 3, "a", true},
		{"a.b.c", 4, "", true},
		{"", 1, "", true},
		{"", 2, "", false},
	}
	for _, tc := range tests {
		got, ok := pythonRelativeBase(tc.pkg, tc.dots)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("pythonRelativeBase(%q, %d) = (%q, %v), want (%q, %v)",
				tc.pkg, tc.dots, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestPythonModuleFQN(t *testing.T) {
	tests := []struct {
		path, root string
		want       FQN
	}{
		{"app/handlers.py", "", "app.handlers"},
		{"/repo/app/handlers.py", "/repo", "app.handlers"},
		{"/repo/app/__init__.py", "/repo", "app"},
		{"/repo/single.py", "/repo", "single"},
	}
	for _, tc := range tests {
		got := pythonModuleFQN(tc.path, tc.root)
		if got != tc.want {
			t.Errorf("pythonModuleFQN(%q, %q) = %q, want %q", tc.path, tc.root, got, tc.want)
		}
	}
}

func keys(m map[FQN]*FuncNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, string(k))
	}
	return out
}
