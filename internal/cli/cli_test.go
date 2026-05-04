package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const piiPolicy = `id: pii-redaction-before-llm
severity: error
languages: [python]
source:
  any_of:
    - calls: app.handlers.load_user
sink:
  any_of:
    - calls: anthropic.messages.create
guard:
  any_of:
    - calls: redactor.redact
message: User PII reaches LLM call without passing through redactor.
`

const piiPolicyNoGuard = `id: pii-bare-llm
severity: error
languages: [python]
source:
  any_of:
    - calls: app.handlers.load_user
sink:
  any_of:
    - calls: anthropic.messages.create
guard:
  any_of:
    - calls: never.matches.guard
message: User PII reaches LLM call.
`

func writePolicy(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheck_NoFindings(t *testing.T) {
	policiesDir := t.TempDir()
	writePolicy(t, policiesDir, "pii.yaml", piiPolicy)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "test",
		[]string{"check", "--policies", policiesDir, "../../tests/fixtures/python/callgraph_basic"},
		&stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "no findings") {
		t.Errorf("stdout = %q, want 'no findings'", stdout.String())
	}
}

func TestCheck_FindsViolation(t *testing.T) {
	policiesDir := t.TempDir()
	writePolicy(t, policiesDir, "pii.yaml", piiPolicyNoGuard)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "test",
		[]string{"check", "--policies", policiesDir, "../../tests/fixtures/python/callgraph_basic"},
		&stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "pii-bare-llm") {
		t.Errorf("stdout = %q; expected pii-bare-llm", out)
	}
	if !strings.Contains(out, "anthropic.messages.create") {
		t.Errorf("stdout = %q; expected sink mention", out)
	}
	if !strings.Contains(out, "1 finding") {
		t.Errorf("stdout = %q; expected count line", out)
	}
}

func TestCheck_MissingPolicies(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "test",
		[]string{"check", "../../tests/fixtures/python/callgraph_basic"},
		&stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--policies or --policy") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestCheck_DuplicatePolicyID(t *testing.T) {
	policiesDir := t.TempDir()
	writePolicy(t, policiesDir, "a.yaml", piiPolicy)
	dup := writePolicy(t, t.TempDir(), "dup.yaml", piiPolicy)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "test",
		[]string{"check", "--policies", policiesDir, "--policy", dup, "../../tests/fixtures/python/callgraph_basic"},
		&stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "duplicate policy id") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

const piiPolicyWithApply = `id: pii-bare-llm
severity: error
languages: [python]
source:
  any_of:
    - calls: app.handlers.load_user
sink:
  any_of:
    - calls: anthropic.messages.create
guard:
  any_of:
    - calls: never.matches.guard
message: User PII reaches LLM call.
fix:
  level: idiomatic
  suggestion: "Wrap with {guard}."
  wrap_argument: 0
`

func TestCheck_ApplyRewritesPositionalArg(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcDir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "app", "__init__.py"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	original := `import anthropic

def summarize(uid):
    user = load_user(uid)
    return anthropic.messages.create(user)

def load_user(uid):
    return {}
`
	srcFile := filepath.Join(srcDir, "app", "handlers.py")
	if err := os.WriteFile(srcFile, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	policiesDir := t.TempDir()
	writePolicy(t, policiesDir, "pii.yaml", piiPolicyWithApply)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "test",
		[]string{"check", "--policies", policiesDir, "--apply", srcDir},
		&stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	got, err := os.ReadFile(srcFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "anthropic.messages.create(never.matches.guard(user))") {
		t.Errorf("file not rewritten as expected; got:\n%s", got)
	}
	if !strings.Contains(stdout.String(), "1 patch(es) applied") {
		t.Errorf("missing apply summary in stdout: %s", stdout.String())
	}
}

func TestCheck_ApplyExits1WhenFindingHasNoPatch(t *testing.T) {
	// piiPolicyNoGuard has no fix block, so findings produce no
	// patches. --apply should exit 1 to flag manual attention.
	policiesDir := t.TempDir()
	writePolicy(t, policiesDir, "pii.yaml", piiPolicyNoGuard)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "test",
		[]string{"check", "--policies", policiesDir, "--apply",
			"../../tests/fixtures/python/policies/pii_redaction_before_llm/violating"},
		&stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "had no structured patch") {
		t.Errorf("expected 'had no structured patch' summary; stdout=%s", stdout.String())
	}
}

func TestCheck_LanguageFilter(t *testing.T) {
	policiesDir := t.TempDir()
	// Policy targets only typescript — should be skipped against python source
	// and yield zero findings.
	tsOnly := strings.Replace(piiPolicyNoGuard, "languages: [python]", "languages: [typescript]", 1)
	writePolicy(t, policiesDir, "ts.yaml", tsOnly)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "test",
		[]string{"check", "--policies", policiesDir, "../../tests/fixtures/python/callgraph_basic"},
		&stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}
