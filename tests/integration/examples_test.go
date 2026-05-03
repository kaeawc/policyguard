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

// runPipeline parses every Python file under srcDir, builds a call graph,
// and analyzes it against p. Returns the findings.
func runPipeline(t *testing.T, srcDir string, p *policy.Policy) []engine.Finding {
	t.Helper()
	var files []*scanner.File
	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
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
		t.Fatalf("walk %s: %v", srcDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no .py files under %s", srcDir)
	}
	g := callgraph.BuildPython(files, srcDir)
	return engine.Analyze(g, p)
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
}
