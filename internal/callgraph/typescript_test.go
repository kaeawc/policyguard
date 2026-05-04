package callgraph

import (
	"context"
	"testing"

	"github.com/kaeawc/policyguard/internal/scanner"
)

func parseTS(t *testing.T, src string) *scanner.File {
	t.Helper()
	f, err := scanner.ParseBytes(context.Background(), "x.ts", scanner.LangTypeScript, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBuildTypeScript_NamedImportResolution(t *testing.T) {
	src := `import { redact } from './redactor';

export function summarize(u: any) {
  return redact(u);
}
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")

	if _, ok := g.Funcs["x.summarize"]; !ok {
		t.Fatalf("missing x.summarize; have %v", funcKeys(g))
	}
	calls := g.Calls["x.summarize"]
	if len(calls) != 1 {
		t.Fatalf("want 1 call, got %d: %+v", len(calls), calls)
	}
	if string(calls[0].Callee) != "./redactor.redact" {
		t.Errorf("Callee = %q, want './redactor.redact'", calls[0].Callee)
	}
}

func TestBuildTypeScript_NamespaceImport(t *testing.T) {
	src := `import * as anthropic from 'anthropic';

export function callLLM() {
  return anthropic.messages.create({});
}
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	calls := g.Calls["x.callLLM"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "anthropic.messages.create" {
		t.Errorf("Callee = %q", calls[0].Callee)
	}
}

func TestBuildTypeScript_AliasedImport(t *testing.T) {
	src := `import { redact as scrub } from './redactor';

export function f() { return scrub(1); }
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	calls := g.Calls["x.f"]
	if len(calls) == 0 {
		t.Fatal("no calls")
	}
	if string(calls[0].Callee) != "./redactor.redact" {
		t.Errorf("Callee = %q, want './redactor.redact' (alias should map to original name)", calls[0].Callee)
	}
}

func TestBuildTypeScript_DefaultImport(t *testing.T) {
	src := `import logger from './logger';

export function f() { return logger.info('hi'); }
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	calls := g.Calls["x.f"]
	if len(calls) == 0 {
		t.Fatal("no calls")
	}
	if string(calls[0].Callee) != "./logger.default.info" {
		t.Errorf("Callee = %q", calls[0].Callee)
	}
}

func TestBuildTypeScript_ArrowFunctionBinding(t *testing.T) {
	src := `import { redact } from './redactor';

const summarize = (u: any) => redact(u);
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	if _, ok := g.Funcs["x.summarize"]; !ok {
		t.Fatalf("missing x.summarize; have %v", funcKeys(g))
	}
	calls := g.Calls["x.summarize"]
	if len(calls) != 1 || string(calls[0].Callee) != "./redactor.redact" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestBuildTypeScript_FunctionExpressionBinding(t *testing.T) {
	src := `import { redact } from './redactor';

const summarize = function (u) { return redact(u); };
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	if _, ok := g.Funcs["x.summarize"]; !ok {
		t.Fatalf("missing x.summarize; have %v", funcKeys(g))
	}
	calls := g.Calls["x.summarize"]
	if len(calls) != 1 || string(calls[0].Callee) != "./redactor.redact" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestBuildTypeScript_ExportedArrowFunction(t *testing.T) {
	src := `import { redact } from './redactor';

export const summarize = (u: any) => redact(u);
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	if _, ok := g.Funcs["x.summarize"]; !ok {
		t.Fatalf("missing x.summarize (export const arrow); have %v", funcKeys(g))
	}
}

func TestBuildTypeScript_ClassMethod(t *testing.T) {
	src := `class Foo {
  bar() { return baz(); }
}
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	if _, ok := g.Funcs["x.Foo.bar"]; !ok {
		t.Fatalf("missing x.Foo.bar; have %v", funcKeys(g))
	}
}

func TestBuildTypeScript_ReceiverTypedParameter(t *testing.T) {
	src := `import { Redactor } from './redactor';

function summarize(r: Redactor, id: string): string {
  return r.redact(id);
}
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	calls := g.Calls["x.summarize"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "./redactor.Redactor.redact" {
		t.Errorf("Callee = %q, want canonical FQN", calls[0].Callee)
	}
}

func TestBuildTypeScript_ReceiverThisMethod(t *testing.T) {
	src := `class Handler {
  helper() { return "x"; }
  run() { return this.helper(); }
}
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	calls := g.Calls["x.Handler.run"]
	if len(calls) != 1 || string(calls[0].Callee) != "x.Handler.helper" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestBuildTypeScript_ReceiverThisFieldMethod(t *testing.T) {
	src := `import { Redactor } from './redactor';

class Handler {
  redactor: Redactor;
  constructor(r: Redactor) { this.redactor = r; }
  call(id: string) { return this.redactor.redact(id); }
}
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	calls := g.Calls["x.Handler.call"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "./redactor.Redactor.redact" {
		t.Errorf("Callee = %q", calls[0].Callee)
	}
}

func TestBuildTypeScript_ReceiverSamePackageType(t *testing.T) {
	// Type isn't imported (defined in same file), falls back to module-FQN.
	src := `class Local {
  run() { return "x"; }
}
function f(l: Local) { return l.run(); }
`
	g := BuildTypeScript([]*scanner.File{parseTS(t, src)}, "")
	calls := g.Calls["x.f"]
	if len(calls) != 1 || string(calls[0].Callee) != "x.Local.run" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestTSModuleFQN(t *testing.T) {
	tests := []struct {
		path, root string
		want       FQN
	}{
		{"src/handler.ts", "", "src.handler"},
		{"/repo/src/handler.tsx", "/repo", "src.handler"},
		{"/repo/src/index.ts", "/repo", "src"},
		{"/repo/lone.ts", "/repo", "lone"},
	}
	for _, tc := range tests {
		got := tsModuleFQN(tc.path, tc.root)
		if got != tc.want {
			t.Errorf("tsModuleFQN(%q, %q) = %q, want %q", tc.path, tc.root, got, tc.want)
		}
	}
}

func funcKeys(g *Graph) []string {
	out := make([]string, 0, len(g.Funcs))
	for k := range g.Funcs {
		out = append(out, string(k))
	}
	return out
}
