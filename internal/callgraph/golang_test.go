package callgraph

import (
	"context"
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
		path, root string
		want       FQN
	}{
		{"cmd/server/main.go", "", "cmd.server"},
		{"/repo/cmd/server/main.go", "/repo", "cmd.server"},
		{"/repo/main.go", "/repo", ""},
	}
	for _, tc := range tests {
		got := goModuleFQN(tc.path, tc.root)
		if got != tc.want {
			t.Errorf("goModuleFQN(%q, %q) = %q, want %q", tc.path, tc.root, got, tc.want)
		}
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
