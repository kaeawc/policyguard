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

func TestAnalyze_ChainsForInterprocedural(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const (
		fetch callgraph.FQN = "svc.h.fetch"
		getU  callgraph.FQN = "svc.h.get_user"
		callL callgraph.FQN = "svc.h.call_llm"
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
		t.Fatalf("findings = %d", len(findings))
	}
	got := findings[0]
	if got := chainFuncs(got.SourceChain); !equalFQNs(got, []callgraph.FQN{fetch, getU}) {
		t.Errorf("SourceChain functions = %v", got)
	}
	if got := chainFuncs(got.SinkChain); !equalFQNs(got, []callgraph.FQN{fetch, callL}) {
		t.Errorf("SinkChain functions = %v", got)
	}
	// Bridge metadata: each hop except the last carries the call-site
	// path/line where this function calls the next one.
	if got.SourceChain[0].Path == "" || got.SourceChain[0].Line == 0 {
		t.Errorf("SourceChain[0] missing bridge: %+v", got.SourceChain[0])
	}
	if got.SourceChain[1].Path != "" || got.SourceChain[1].Line != 0 {
		t.Errorf("SourceChain[last] should have no bridge: %+v", got.SourceChain[1])
	}
}

func chainFuncs(chain []ChainHop) []callgraph.FQN {
	out := make([]callgraph.FQN, len(chain))
	for i, h := range chain {
		out[i] = h.Function
	}
	return out
}

func TestAnalyze_ChainsForIntraprocedural(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))

	findings := Analyze(g, basicPolicy())
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	want := []callgraph.FQN{fn}
	if got := chainFuncs(findings[0].SourceChain); !equalFQNs(got, want) {
		t.Errorf("SourceChain = %v", got)
	}
	if got := chainFuncs(findings[0].SinkChain); !equalFQNs(got, want) {
		t.Errorf("SinkChain = %v", got)
	}
}

func equalFQNs(a, b []callgraph.FQN) bool {
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

func TestAnalyze_BuildsWrapPatchForPositionalArg(t *testing.T) {
	// Real Python source so the sink CallSite has a valid AST node.
	src := []byte(`import anthropic

def f(user_id):
    user = load_user(user_id)
    return anthropic.messages.create(user)

def load_user(user_id):
    return {"id": user_id}
`)
	file, err := scanner.ParseBytes(context.Background(), "x.py", scanner.LangPython, src)
	if err != nil {
		t.Fatal(err)
	}
	g := callgraph.BuildPython([]*scanner.File{file}, "")

	p := basicPolicy()
	p.Source = policy.Matcher{AnyOf: []policy.Predicate{{Calls: "x.load_user"}}}
	p.Sink = policy.Matcher{AnyOf: []policy.Predicate{{Calls: "anthropic.messages.create"}}}
	zero := 0
	p.Fix = &policy.Fix{
		Level:        policy.FixIdiomatic,
		Suggestion:   "wrap it",
		WrapArgument: &zero,
	}

	findings := Analyze(g, p)
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	patch := findings[0].Fix.Patch
	if patch == nil {
		t.Fatalf("expected patch, got nil")
	}
	if patch.NewLine != "    return anthropic.messages.create(redactor.redact(user))" {
		t.Errorf("NewLine = %q", patch.NewLine)
	}
	if patch.Line != 5 {
		t.Errorf("Line = %d, want 5", patch.Line)
	}
	if !strings.Contains(patch.UnifiedDiff(), "+    return anthropic.messages.create(redactor.redact(user))") {
		t.Errorf("UnifiedDiff missing +line; got %q", patch.UnifiedDiff())
	}
}

func TestAnalyze_NoPatchWhenSinkUsesKeywordArgs(t *testing.T) {
	// All args are keyword args — wrap_argument: 0 has no positional
	// arg to wrap, so the engine emits the suggestion text but no Patch.
	src := []byte(`import anthropic

def f(user_id):
    user = load_user(user_id)
    return anthropic.messages.create(model="x", input=user)

def load_user(user_id):
    return {}
`)
	file, err := scanner.ParseBytes(context.Background(), "x.py", scanner.LangPython, src)
	if err != nil {
		t.Fatal(err)
	}
	g := callgraph.BuildPython([]*scanner.File{file}, "")
	p := basicPolicy()
	p.Source = policy.Matcher{AnyOf: []policy.Predicate{{Calls: "x.load_user"}}}
	p.Sink = policy.Matcher{AnyOf: []policy.Predicate{{Calls: "anthropic.messages.create"}}}
	zero := 0
	p.Fix = &policy.Fix{
		Level:        policy.FixIdiomatic,
		Suggestion:   "wrap it",
		WrapArgument: &zero,
	}
	findings := Analyze(g, p)
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Fix.Patch != nil {
		t.Errorf("expected no patch (only kwargs); got %+v", findings[0].Fix.Patch)
	}
}

func TestAnalyze_RendersFixTemplate(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))

	p := basicPolicy()
	p.Fix = &policy.Fix{
		Level:      policy.FixIdiomatic,
		Suggestion: "Wrap the user object in {guard} before {sink.callee} at line {sink.line}.",
	}

	findings := Analyze(g, p)
	if len(findings) != 1 || findings[0].Fix == nil {
		t.Fatalf("findings = %+v", findings)
	}
	got := findings[0].Fix.Suggestion
	want := "Wrap the user object in redactor.redact before anthropic.messages.create at line 3."
	if got != want {
		t.Errorf("Suggestion = %q\nwant %q", got, want)
	}
	if findings[0].Fix.Level != policy.FixIdiomatic {
		t.Errorf("Level = %q", findings[0].Fix.Level)
	}
}

func TestAnalyze_NoFixWhenPolicyOmitsFix(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))

	findings := Analyze(g, basicPolicy())
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Fix != nil {
		t.Errorf("expected nil Fix, got %+v", findings[0].Fix)
	}
}

func TestAnalyze_SuppressionByExactID(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))
	// Suppression on line 2 covers lines 2 and 3 (line+1 rule).
	g.AddSuppression(callgraph.Suppression{
		Path:      "svc/h.py",
		Line:      2,
		PolicyIDs: []string{"pii-redaction-before-llm"},
	})

	if got := Analyze(g, basicPolicy()); len(got) != 0 {
		t.Errorf("expected no findings (suppressed), got %+v", got)
	}
}

func TestAnalyze_SuppressionWildcard(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))
	g.AddSuppression(callgraph.Suppression{
		Path:      "svc/h.py",
		Line:      3,
		PolicyIDs: []string{"*"},
	})

	if got := Analyze(g, basicPolicy()); len(got) != 0 {
		t.Errorf("expected no findings (wildcard suppression), got %+v", got)
	}
}

func TestAnalyze_SuppressionDifferentPolicyIgnored(t *testing.T) {
	g := callgraph.NewGraph()
	f := fakeFile("svc/h.py")
	const fn callgraph.FQN = "svc.h.fetch"
	g.AddFunc(&callgraph.FuncNode{FQN: fn, File: f, Line: 1})
	g.AddCall(fakeCall(fn, "user_repo.get_user", f, 2))
	g.AddCall(fakeCall(fn, "anthropic.messages.create", f, 3))
	g.AddSuppression(callgraph.Suppression{
		Path:      "svc/h.py",
		Line:      3,
		PolicyIDs: []string{"some-other-policy"},
	})

	if got := Analyze(g, basicPolicy()); len(got) != 1 {
		t.Errorf("expected finding (suppression mismatch), got %+v", got)
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
