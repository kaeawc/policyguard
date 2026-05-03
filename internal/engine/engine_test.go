package engine

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/policy"
	"github.com/kaeawc/policyguard/internal/scanner"
)

// fakeFile builds a *scanner.File without parsing real source — Source/Node
// are nil because the engine only reads File.Path and CallSite.Line.
func fakeFile(path string) *scanner.File {
	return &scanner.File{Path: path, Language: scanner.LangPython}
}

// fakeCall constructs a CallSite. The Node field is nil; the engine never
// dereferences it in Analyze.
func fakeCall(caller, callee callgraph.FQN, file *scanner.File, line int) *callgraph.CallSite {
	return &callgraph.CallSite{
		Caller: caller,
		Callee: callee,
		Raw:    string(callee),
		File:   file,
		Line:   line,
	}
}

func basicPolicy() *policy.Policy {
	return &policy.Policy{
		ID:        "pii-redaction-before-llm",
		Severity:  policy.SeverityError,
		Languages: []policy.Language{policy.LangPython},
		Source: policy.Matcher{AnyOf: []policy.Predicate{
			{Calls: "user_repo.get_user"},
		}},
		Sink: policy.Matcher{AnyOf: []policy.Predicate{
			{Calls: "anthropic.messages.create"},
		}},
		Guard: policy.Matcher{AnyOf: []policy.Predicate{
			{Calls: "redactor.redact"},
		}},
		Message: "User PII reaches LLM call without passing through redactor.",
	}
}

func TestAnalyze_ViolationWhenNoGuard(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/handler.py")
	const fn callgraph.FQN = "svc.handler.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))

	findings := Analyze(g, basicPolicy())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.Function != fn {
		t.Errorf("Function = %q, want %q", got.Function, fn)
	}
	if got.Source.Callee != "user_repo.get_user" || got.Source.Line != 2 {
		t.Errorf("Source = %+v", got.Source)
	}
	if got.Sink.Callee != "anthropic.messages.create" || got.Sink.Line != 3 {
		t.Errorf("Sink = %+v", got.Sink)
	}
}

func TestAnalyze_NoViolationWhenGuarded(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/handler.py")
	const fn callgraph.FQN = "svc.handler.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "redactor.redact", f, 3))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 4))

	if got := Analyze(g, basicPolicy()); len(got) != 0 {
		t.Fatalf("expected no findings, got %+v", got)
	}
}

func TestAnalyze_NoViolationWhenSourceMissing(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/handler.py")
	const fn callgraph.FQN = "svc.handler.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 4))

	if got := Analyze(g, basicPolicy()); len(got) != 0 {
		t.Fatalf("expected no findings (no source), got %+v", got)
	}
}

func TestAnalyze_NoViolationWhenSinkMissing(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/handler.py")
	const fn callgraph.FQN = "svc.handler.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))

	if got := Analyze(g, basicPolicy()); len(got) != 0 {
		t.Fatalf("expected no findings (no sink), got %+v", got)
	}
}

func TestAnalyze_WildcardCallsMatcher(t *testing.T) {
	p := basicPolicy()
	p.Sink = policy.Matcher{AnyOf: []policy.Predicate{{Calls: "anthropic.*"}}}

	g := callgraph.NewGraph()
	f := fakeFile("svc/handler.py")
	const fn callgraph.FQN = "svc.handler.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))

	findings := Analyze(g, p)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
}

func TestAnalyze_FindingsSortedDeterministically(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	for _, fn := range []callgraph.FQN{"svc.h.b", "svc.h.a", "svc.h.c"} {
		g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
		g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
		g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))
	}
	findings := Analyze(g, basicPolicy())
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(findings))
	}
	want := []callgraph.FQN{"svc.h.a", "svc.h.b", "svc.h.c"}
	for i, f := range findings {
		if f.Function != want[i] {
			t.Errorf("findings[%d].Function = %q, want %q", i, f.Function, want[i])
		}
	}
}

func TestAnalyze_InterproceduralViolation(t *testing.T) {
	// fetch_summary calls get_user (source) and call_llm (sink); no guard
	// anywhere. fetch_summary's closure should contain both.
	g := callgraph.NewGraph()
	f := fakeFile("svc/handler.py")
	const (
		fetch callgraph.FQN = "svc.handler.fetch_summary"
		getU  callgraph.FQN = "svc.handler.get_user"
		callL callgraph.FQN = "svc.handler.call_llm"
	)
	for _, fn := range []callgraph.FQN{fetch, getU, callL} {
		g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	}
	g.AddCall(fakeCall(fetch, getU, f, 2))
	g.AddCall(fakeCall(fetch, callL, f, 3))
	g.AddCall(fakeCall(getU, "user_repo.get_user", f, 11))
	g.AddCall(fakeCall(callL, "anthropic.messages.create", f, 21))

	findings := Analyze(g, basicPolicy())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.Function != fetch {
		t.Errorf("Function = %q, want %q (the minimal common ancestor)", got.Function, fetch)
	}
	if string(got.Source.Callee) != "user_repo.get_user" {
		t.Errorf("Source.Callee = %q", got.Source.Callee)
	}
	if string(got.Sink.Callee) != "anthropic.messages.create" {
		t.Errorf("Sink.Callee = %q", got.Sink.Callee)
	}
}

func TestAnalyze_InterproceduralGuardOnTransitivePath(t *testing.T) {
	// fetch_summary -> get_user (source) -> redactor.redact (guard).
	// The guard is in get_user's closure; fetch_summary's closure inherits
	// it. No violation.
	g := callgraph.NewGraph()
	f := fakeFile("svc/handler.py")
	const (
		fetch callgraph.FQN = "svc.handler.fetch_summary"
		getU  callgraph.FQN = "svc.handler.get_user"
		callL callgraph.FQN = "svc.handler.call_llm"
	)
	for _, fn := range []callgraph.FQN{fetch, getU, callL} {
		g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	}
	g.AddCall(fakeCall(fetch, getU, f, 2))
	g.AddCall(fakeCall(fetch, callL, f, 3))
	g.AddCall(fakeCall(getU, "user_repo.get_user", f, 11))
	g.AddCall(fakeCall(getU, "redactor.redact", f, 12)) // guard
	g.AddCall(fakeCall(callL, "anthropic.messages.create", f, 21))

	if findings := Analyze(g, basicPolicy()); len(findings) != 0 {
		t.Fatalf("expected no findings (guard on path), got %+v", findings)
	}
}

func TestAnalyze_MinimalViolatorDedup(t *testing.T) {
	// outer -> inner; inner is intra-procedural violator. outer also
	// "inherits" the violation via closure but should be suppressed —
	// inner is the smaller, more localized site to report.
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const (
		outer callgraph.FQN = "svc.h.outer"
		inner callgraph.FQN = "svc.h.inner"
	)
	for _, fn := range []callgraph.FQN{outer, inner} {
		g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	}
	g.AddCall(fakeCall(outer, inner, f, 2))
	g.AddCall(fakeCall(inner, "user_repo.get_user", f, 11))
	g.AddCall(fakeCall(inner, "anthropic.messages.create", f, 12))

	findings := Analyze(g, basicPolicy())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only inner): %+v", len(findings), findings)
	}
	if findings[0].Function != inner {
		t.Errorf("Function = %q, want %q", findings[0].Function, inner)
	}
}

func TestAnalyze_DecoratorGuardSuppresses(t *testing.T) {
	// fetch has source + sink and would violate by call-site analysis
	// alone, but it carries the @redacted decorator — the policy's
	// has_decorator guard fires and the violation is suppressed.
	g := callgraph.NewGraph()
	f := fakeFile("svc/handler.py")
	const fn callgraph.FQN = "svc.handler.fetch"
	g.AddFunc(&callgraph.FuncNode{
		FQN:        fn,
		File:       f,
		Line:       1,
		Decorators: []string{"redacted"},
	})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))

	p := basicPolicy()
	p.Guard = policy.Matcher{AnyOf: []policy.Predicate{
		{HasDecorator: "@redacted"},
	}}
	if got := Analyze(g, p); len(got) != 0 {
		t.Fatalf("expected no findings (decorator guard), got %+v", got)
	}
}

func TestAnalyze_DecoratorGuardOnTransitiveCallee(t *testing.T) {
	// outer calls inner; inner has source + sink; inner is decorated
	// with @auth.required which the policy lists as a guard. Even
	// though the call-site set in inner's closure has both source and
	// sink, the decorator on inner suppresses the finding for both
	// inner and outer.
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const (
		outer callgraph.FQN = "svc.h.outer"
		inner callgraph.FQN = "svc.h.inner"
	)
	g.AddFunc(&callgraph.FuncNode{FQN: outer, File: f, Line: 1})
	g.AddFunc(&callgraph.FuncNode{FQN: inner, File: f, Line: 1, Decorators: []string{"auth.required"}})
	g.AddCall(fakeCall(outer, inner, f, 2))
	g.AddCall(fakeCall(inner, "user_repo.get_user", f, 11))
	g.AddCall(fakeCall(inner, "anthropic.messages.create", f, 12))

	p := basicPolicy()
	p.Guard = policy.Matcher{AnyOf: []policy.Predicate{
		{HasDecorator: "@auth.required"},
	}}
	if got := Analyze(g, p); len(got) != 0 {
		t.Fatalf("expected no findings (transitive decorator guard), got %+v", got)
	}
}

func fakeField(caller callgraph.FQN, path, field string, file *scanner.File, line int) *callgraph.FieldAccess {
	return &callgraph.FieldAccess{
		Caller: caller,
		Field:  field,
		Path:   path,
		File:   file,
		Line:   line,
	}
}

func TestAnalyze_FieldAccessAsSource_WildcardField(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddField(fakeField(fn, "user.email", "email", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))

	p := basicPolicy()
	p.Source = policy.Matcher{AnyOf: []policy.Predicate{
		{FieldAccess: "*.email"},
	}}
	findings := Analyze(g, p)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if string(findings[0].Source.Callee) != "user.email" {
		t.Errorf("Source.Callee = %q, want 'user.email' (the field-access path)", findings[0].Source.Callee)
	}
	if findings[0].Source.Line != 2 {
		t.Errorf("Source.Line = %d, want 2", findings[0].Source.Line)
	}
}

func TestAnalyze_FieldAccessAsSource_ExactPath(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddField(fakeField(fn, "request.body.path", "path", f, 2))
	g.AddField(fakeField(fn, "user.email", "email", f, 3))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 4))

	p := basicPolicy()
	// Exact path match — only request.body.path should fire, not user.email.
	p.Source = policy.Matcher{AnyOf: []policy.Predicate{
		{FieldAccess: "request.body.path"},
	}}
	findings := Analyze(g, p)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if string(findings[0].Source.Callee) != "request.body.path" {
		t.Errorf("Source.Callee = %q", findings[0].Source.Callee)
	}
}

func TestAnalyze_FieldAccessSourceWithCallSink(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	// Source is a field access; sink is a call. Mixed source/sink kinds.
	g.AddField(fakeField(fn, "user.email", "email", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))

	p := basicPolicy()
	p.Source = policy.Matcher{AnyOf: []policy.Predicate{
		{FieldAccess: "*.email"},
	}}
	findings := Analyze(g, p)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if string(findings[0].Sink.Callee) != "anthropic.messages.create" {
		t.Errorf("Sink.Callee = %q", findings[0].Sink.Callee)
	}
}

func TestAnalyze_HandlesCycles(t *testing.T) {
	// a -> b -> a (cycle). a has the source, b has the sink. The
	// closure walker must terminate.
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const (
		a callgraph.FQN = "svc.h.a"
		b callgraph.FQN = "svc.h.b"
	)
	for _, fn := range []callgraph.FQN{a, b} {
		g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	}
	g.AddCall(fakeCall(a, b, f, 2))
	g.AddCall(fakeCall(b, a, f, 3))
	g.AddCall(fakeCall(a, "user_repo.get_user", f, 11))
	g.AddCall(fakeCall(b, "anthropic.messages.create", f, 21))

	findings := Analyze(g, basicPolicy())
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding, got none")
	}
	// Both a and b are violators (cycle ⇒ closures equal). After dedup
	// neither is "smaller", so dedup keeps both. Either is acceptable as
	// a cycle response — assert at least the policy fires and we
	// terminate.
}

// Integration test: drive the engine through the real call graph from the
// existing fixture under tests/fixtures/python/callgraph_basic.
func TestAnalyze_IntegrationFixture(t *testing.T) {
	root := "../../tests/fixtures/python/callgraph_basic"
	files := loadPythonDir(t, root)
	g := callgraph.BuildPython(files, root)

	// With redactor.redact present the fixture should be clean.
	if got := Analyze(g, basicPolicy()); len(got) != 0 {
		t.Errorf("guarded fixture: expected no findings, got %+v", got)
	}

	// Drop the guard and the same fixture should now report a violation.
	noGuardPolicy := basicPolicy()
	noGuardPolicy.Source = policy.Matcher{AnyOf: []policy.Predicate{
		{Calls: "app.handlers.load_user"},
	}}
	noGuardPolicy.Guard = policy.Matcher{AnyOf: []policy.Predicate{
		{Calls: "nonexistent.guard"},
	}}
	findings := Analyze(g, noGuardPolicy)
	if len(findings) != 1 {
		t.Fatalf("ungated fixture: findings = %d, want 1: %+v", len(findings), findings)
	}
	if !strings.HasPrefix(string(findings[0].Function), "app.handlers.fetch_user_summary") {
		t.Errorf("Function = %q", findings[0].Function)
	}
}

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
