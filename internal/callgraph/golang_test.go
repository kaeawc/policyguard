package callgraph

import (
	"context"
	"os"
	"testing"

	"github.com/kaeawc/policyguard/internal/scanner"
)

func parseGo(t *testing.T, path, src string) *scanner.File {
	t.Helper()
	f, err := scanner.ParseBytes(context.Background(), path, scanner.LangGo, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBuildGo_BareImportResolution(t *testing.T) {
	src := `package handler
import "redactor"
func F(x string) string { return redactor.Redact(x) }
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	calls := g.Calls["handler.F"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "redactor.Redact" {
		t.Errorf("Callee = %q", calls[0].Callee)
	}
}

func TestBuildGo_AliasedImport(t *testing.T) {
	src := `package handler
import llm "github.com/anthropic/anthropic-sdk-go"
func F() string { return llm.Messages.Create(nil) }
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	calls := g.Calls["handler.F"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "github.com/anthropic/anthropic-sdk-go.Messages.Create" {
		t.Errorf("Callee = %q", calls[0].Callee)
	}
}

func TestBuildGo_ModuleLocalCall(t *testing.T) {
	src := `package handler
func F() string { return loadUser("x") }
func loadUser(id string) string { return id }
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	calls := g.Calls["handler.F"]
	if len(calls) == 0 {
		t.Fatal("no calls")
	}
	if string(calls[0].Callee) != "handler.loadUser" {
		t.Errorf("Callee = %q, want 'handler.loadUser'", calls[0].Callee)
	}
}

func TestBuildGo_MethodReceiverFQN(t *testing.T) {
	src := `package handler
type Foo struct{}
func (f *Foo) Bar() string { return "x" }
func (f Foo) Baz() string { return "y" }
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	for _, want := range []FQN{"handler.Foo.Bar", "handler.Foo.Baz"} {
		if _, ok := g.Funcs[want]; !ok {
			t.Errorf("missing %q; have %v", want, funcKeys(g))
		}
	}
}

func TestBuildGo_ReceiverTypedParameter(t *testing.T) {
	// f's parameter `r` has type *redactor.Redactor (imported). The
	// `r.Redact(x)` call should resolve to the canonical FQN.
	src := `package handler
import "example.com/redactor"
func F(r *redactor.Redactor) string { return r.Redact("x") }
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	calls := g.Calls["handler.F"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "example.com/redactor.Redactor.Redact" {
		t.Errorf("Callee = %q, want canonical FQN", calls[0].Callee)
	}
	if calls[0].Raw != "r.Redact" {
		t.Errorf("Raw = %q, want 'r.Redact'", calls[0].Raw)
	}
}

func TestBuildGo_ReceiverTypedMethodReceiver(t *testing.T) {
	// h is the method receiver, a *Handler. Calls like `h.helper()`
	// resolve to <pkg>.Handler.helper.
	src := `package handler
type Handler struct{}
func (h *Handler) F() string { return h.helper() }
func (h *Handler) helper() string { return "x" }
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	calls := g.Calls["handler.Handler.F"]
	if len(calls) != 1 || string(calls[0].Callee) != "handler.Handler.helper" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestBuildGo_TypeInferenceFromShortVarDecl(t *testing.T) {
	// `r := makeRedactor()` infers r as *redactor.Redactor (return type
	// of makeRedactor) so `r.Redact(x)` resolves to the canonical FQN.
	src := `package handler
import "example.com/redactor"
func makeRedactor() *redactor.Redactor { return nil }
func F() string {
    r := makeRedactor()
    return r.Redact("x")
}
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	calls := g.Calls["handler.F"]
	var rRedact *CallSite
	for _, c := range calls {
		if c.Raw == "r.Redact" {
			rRedact = c
		}
	}
	if rRedact == nil {
		t.Fatalf("missing r.Redact; got %+v", calls)
	}
	if string(rRedact.Callee) != "example.com/redactor.Redactor.Redact" {
		t.Errorf("Callee = %q", rRedact.Callee)
	}
}

func TestBuildGo_TypeInferenceSamePackageReturn(t *testing.T) {
	src := `package handler
type Local struct{}
func make() *Local { return nil }
func F() string {
    l := make()
    return l.Run()
}
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	calls := g.Calls["handler.F"]
	for _, c := range calls {
		if c.Raw == "l.Run" {
			if string(c.Callee) != "handler.Local.Run" {
				t.Errorf("Callee = %q, want handler.Local.Run", c.Callee)
			}
			return
		}
	}
	t.Fatalf("missing l.Run; calls = %+v", calls)
}

func TestBuildGo_TypeInferenceSkipsMultiReturn(t *testing.T) {
	// Multi-return (Local, error) doesn't yield an inference; the
	// `l.Run()` call falls back to raw text resolution.
	src := `package handler
type Local struct{}
func make() (*Local, error) { return nil, nil }
func F() string {
    l, _ := make()
    return l.Run()
}
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	for _, c := range g.Calls["handler.F"] {
		if c.Raw == "l.Run" {
			if string(c.Callee) == "handler.Local.Run" {
				t.Errorf("Callee = %q (multi-return should not infer)", c.Callee)
			}
			return
		}
	}
}

func TestBuildGo_ReceiverTypedSamePackageType(t *testing.T) {
	// Parameter type is in the same package; resolves to <pkg>.<TypeName>.<method>.
	src := `package handler
type Local struct{}
func F(l *Local) string { return l.Run() }
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	calls := g.Calls["handler.F"]
	if len(calls) != 1 || string(calls[0].Callee) != "handler.Local.Run" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestBuildGo_ImportSkipsBlankAndDot(t *testing.T) {
	src := `package handler

import (
	_ "side-effect"
	. "math"
)

func F() float64 { return Pi }
`
	g := BuildGo([]*scanner.File{parseGo(t, "handler/handler.go", src)}, "")
	if _, ok := g.Funcs["handler.F"]; !ok {
		t.Fatalf("missing handler.F")
	}
	// blank/dot imports must not enter the import map; module-local
	// fallback applies. Pi is a field-access (selector_expression) but
	// here it's a bare identifier, so we just assert no crash.
}

func TestGoModuleFQN(t *testing.T) {
	tests := []struct {
		path, root, mod string
		want            FQN
	}{
		// Legacy dot-form (no go.mod available)
		{"cmd/server/main.go", "", "", "cmd.server"},
		{"/repo/cmd/server/main.go", "/repo", "", "cmd.server"},
		{"/repo/main.go", "/repo", "", ""},
		// Module-rooted form when go.mod is present
		{"/repo/cmd/server/main.go", "/repo", "github.com/me/proj", "github.com/me/proj/cmd/server"},
		{"/repo/main.go", "/repo", "github.com/me/proj", "github.com/me/proj"},
	}
	for _, tc := range tests {
		got := goModuleFQN(tc.path, tc.root, tc.mod)
		if got != tc.want {
			t.Errorf("goModuleFQN(%q, %q, %q) = %q, want %q", tc.path, tc.root, tc.mod, got, tc.want)
		}
	}
}

func TestParseGoModFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/go.mod"
	body := `module github.com/me/proj

go 1.25.0
require example.com/foo v1.0.0
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := parseGoModFile(path); got != "github.com/me/proj" {
		t.Errorf("parseGoModFile = %q", got)
	}
	// Missing file → empty string, not an error.
	if got := parseGoModFile(dir + "/no-such.mod"); got != "" {
		t.Errorf("missing file: got %q", got)
	}
}

func TestFindGoModulePath_AncestorWalk(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(root+"/go.mod", []byte("module example.com/abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := root + "/cmd/server"
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := findGoModulePath(sub); got != "example.com/abc" {
		t.Errorf("findGoModulePath = %q", got)
	}
}

func TestBuildGo_CrossFileResolutionWithGoMod(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(root+"/go.mod", []byte("module example.com/proj\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/handler", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/redactor", 0o755); err != nil {
		t.Fatal(err)
	}
	handler, err := scanner.ParseBytes(context.Background(),
		root+"/handler/handler.go", scanner.LangGo,
		[]byte(`package handler
import "example.com/proj/redactor"
func F(x string) string { return redactor.Redact(x) }
`))
	if err != nil {
		t.Fatal(err)
	}
	redactorFile, err := scanner.ParseBytes(context.Background(),
		root+"/redactor/redactor.go", scanner.LangGo,
		[]byte(`package redactor
func Redact(x string) string { return x }
`))
	if err != nil {
		t.Fatal(err)
	}
	g := BuildGo([]*scanner.File{handler, redactorFile}, root)
	want := FQN("example.com/proj/redactor.Redact")
	if _, ok := g.Funcs[want]; !ok {
		t.Fatalf("missing %q; have %v", want, funcKeys(g))
	}
	calls := g.Calls["example.com/proj/handler.F"]
	if len(calls) != 1 || calls[0].Callee != want {
		t.Errorf("calls = %+v, want callee = %q", calls, want)
	}
}

func TestGoLastSegment(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"github.com/foo/bar", "bar"},
		{"github.com/foo/bar/v2", "bar"},
		{"github.com/foo/bar/v2/sub", "sub"},
		{"single", "single"},
	}
	for _, tc := range tests {
		got := goLastSegment(tc.in)
		if got != tc.want {
			t.Errorf("goLastSegment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
