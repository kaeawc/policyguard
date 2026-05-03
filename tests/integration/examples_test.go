// Package integration runs the full pipeline (parse → call graph →
// engine) against each example policy under examples/policies/ and its
// matched compliant/violating fixture trees. These tests prove the
// canonical policies stay in sync with the engine.
package integration

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/engine"
	"github.com/kaeawc/policyguard/internal/policy"
	"github.com/kaeawc/policyguard/internal/scanner"
)

// repoRoot returns the path to the repository root, derived from the
// location of this test file (tests/integration → ../..).
func repoRoot(t *testing.T) string {
	t.Helper()
	// The Go test runner runs from the package directory, so the working
	// directory is tests/integration/. Two levels up is the repo root.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// runPipeline parses every source file under srcDir matching the
// policy's first declared language, builds a call graph, and analyzes
// it. Currently supports Python and TypeScript.
func runPipeline(t *testing.T, srcDir string, p *policy.Policy) []engine.Finding {
	t.Helper()
	if len(p.Languages) == 0 {
		t.Fatalf("policy %q has no languages", p.ID)
	}
	lang := p.Languages[0]
	var sLang scanner.Language
	var exts []string
	switch lang {
	case policy.LangPython:
		sLang = scanner.LangPython
		exts = []string{".py"}
	case policy.LangTypeScript:
		sLang = scanner.LangTypeScript
		exts = []string{".ts", ".tsx"}
	default:
		t.Fatalf("integration test does not support language %q", lang)
	}
	matchExt := func(p string) bool {
		for _, ext := range exts {
			if strings.HasSuffix(p, ext) {
				return true
			}
		}
		return false
	}
	var files []*scanner.File
	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !matchExt(path) {
			return nil
		}
		f, perr := scanner.ParseFile(context.Background(), path, sLang)
		if perr != nil {
			return perr
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", srcDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no %s files under %s", sLang, srcDir)
	}
	var g *callgraph.Graph
	switch sLang {
	case scanner.LangPython:
		g = callgraph.BuildPython(files, srcDir)
	case scanner.LangTypeScript:
		g = callgraph.BuildTypeScript(files, srcDir)
	}
	return engine.Analyze(g, p)
}

// runExample loads policy at policyRel (relative to repo root) and runs
// the pipeline against the compliant + violating fixtures under
// fixtureRel. wantSink is the expected sink callee in the violating run.
func runExample(t *testing.T, policyRel, fixtureRel, wantSink string) {
	t.Helper()
	root := repoRoot(t)
	p, err := policy.Load(filepath.Join(root, policyRel))
	if err != nil {
		t.Fatalf("Load policy %s: %v", policyRel, err)
	}

	t.Run("compliant", func(t *testing.T) {
		dir := filepath.Join(root, fixtureRel, "compliant")
		findings := runPipeline(t, dir, p)
		if len(findings) != 0 {
			t.Errorf("expected no findings, got %+v", findings)
		}
	})

	t.Run("violating", func(t *testing.T) {
		dir := filepath.Join(root, fixtureRel, "violating")
		findings := runPipeline(t, dir, p)
		if len(findings) != 1 {
			t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
		}
		if findings[0].PolicyID != p.ID {
			t.Errorf("PolicyID = %q, want %q", findings[0].PolicyID, p.ID)
		}
		if string(findings[0].Sink.Callee) != wantSink {
			t.Errorf("Sink.Callee = %q, want %q", findings[0].Sink.Callee, wantSink)
		}
	})
}

func TestExample_PIIRedactionBeforeLLM(t *testing.T) {
	root := repoRoot(t)
	p, err := policy.Load(filepath.Join(root, "examples/policies/pii-redaction-before-llm.yaml"))
	if err != nil {
		t.Fatalf("Load policy: %v", err)
	}
	if p.ID != "pii-redaction-before-llm" {
		t.Fatalf("policy ID = %q", p.ID)
	}

	t.Run("compliant", func(t *testing.T) {
		fix := filepath.Join(root, "tests/fixtures/python/policies/pii_redaction_before_llm/compliant")
		findings := runPipeline(t, fix, p)
		if len(findings) != 0 {
			t.Errorf("expected no findings, got %+v", findings)
		}
	})

	t.Run("violating", func(t *testing.T) {
		fix := filepath.Join(root, "tests/fixtures/python/policies/pii_redaction_before_llm/violating")
		findings := runPipeline(t, fix, p)
		if len(findings) != 1 {
			t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
		}
		got := findings[0]
		if got.PolicyID != p.ID {
			t.Errorf("PolicyID = %q", got.PolicyID)
		}
		if string(got.Sink.Callee) != "anthropic.messages.create" {
			t.Errorf("Sink.Callee = %q", got.Sink.Callee)
		}
		if !strings.Contains(string(got.Function), "summarize_user") {
			t.Errorf("Function = %q, want contains summarize_user", got.Function)
		}
	})

	t.Run("compliant_decorated", func(t *testing.T) {
		// summarize_user is decorated with @redacted; the policy lists
		// has_decorator: "@redacted" as a guard. No findings expected.
		fix := filepath.Join(root, "tests/fixtures/python/policies/pii_redaction_before_llm/compliant_decorated")
		findings := runPipeline(t, fix, p)
		if len(findings) != 0 {
			t.Errorf("expected no findings (decorator guard), got %+v", findings)
		}
	})

	t.Run("violating_field_access", func(t *testing.T) {
		// Source via field_access: "*.email" — function reads user.email
		// then hands to anthropic without redaction.
		fix := filepath.Join(root, "tests/fixtures/python/policies/pii_redaction_before_llm/violating_field_access")
		findings := runPipeline(t, fix, p)
		if len(findings) != 1 {
			t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
		}
		got := findings[0]
		if string(got.Source.Callee) != "user.email" {
			t.Errorf("Source.Callee = %q, want 'user.email'", got.Source.Callee)
		}
	})

	t.Run("violating_interprocedural", func(t *testing.T) {
		// Source in get_user, sink in call_llm, no guard anywhere.
		// fetch_summary is the common ancestor whose closure spans both.
		fix := filepath.Join(root, "tests/fixtures/python/policies/pii_redaction_before_llm/violating_interprocedural")
		findings := runPipeline(t, fix, p)
		if len(findings) != 1 {
			t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
		}
		got := findings[0]
		if !strings.Contains(string(got.Function), "fetch_summary") {
			t.Errorf("Function = %q, want contains fetch_summary", got.Function)
		}
		if string(got.Sink.Callee) != "anthropic.messages.create" {
			t.Errorf("Sink.Callee = %q", got.Sink.Callee)
		}
	})
}

func TestExample_LogUserMustRedact(t *testing.T) {
	runExample(t,
		"examples/policies/log-user-must-redact.yaml",
		"tests/fixtures/python/policies/log_user_must_redact",
		"logging.info",
	)
}

func TestExample_PIIRedactionBeforeLLM_TypeScript(t *testing.T) {
	runExample(t,
		"examples/policies/pii-redaction-before-llm-ts.yaml",
		"tests/fixtures/typescript/policies/pii_redaction_before_llm",
		"anthropic.messages.create",
	)
}

func TestExample_PathConfinement(t *testing.T) {
	runExample(t,
		"examples/policies/path-confinement.yaml",
		"tests/fixtures/python/policies/path_confinement",
		// "open" is matched via the engine's raw-text fallback because
		// the resolver maps the bare builtin to a module-local FQN.
		// runExample asserts on the resolved Sink.Callee, which for
		// `open(...)` becomes <module>.open. We pin the violating
		// fixture's module so this stays stable.
		"app.handlers.open",
	)
}
