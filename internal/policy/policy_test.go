package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yaml", minimal("policy-a"))
	write("b.yml", minimal("policy-b"))
	write("ignore.txt", "not a policy")

	policies, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("len(policies) = %d, want 2", len(policies))
	}
	if policies[0].ID != "policy-a" || policies[1].ID != "policy-b" {
		t.Errorf("ids = %q, %q", policies[0].ID, policies[1].ID)
	}
}

func TestLoadDir_DuplicateID(t *testing.T) {
	dir := t.TempDir()
	body := minimal("dup")
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "duplicate policy id") {
		t.Fatalf("LoadDir: expected duplicate-id error, got %v", err)
	}
}

func TestLoad_Valid(t *testing.T) {
	p, err := Load(filepath.Join("testdata", "valid_pii_redaction.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.ID != "pii-redaction-before-llm" {
		t.Errorf("ID = %q", p.ID)
	}
	if p.Severity != SeverityError {
		t.Errorf("Severity = %q", p.Severity)
	}
	if got := len(p.Languages); got != 3 {
		t.Errorf("len(Languages) = %d, want 3", got)
	}
	if got := len(p.Source.AnyOf); got != 3 {
		t.Errorf("len(Source.AnyOf) = %d, want 3", got)
	}
	if p.Source.AnyOf[2].Kind() != "field_access" {
		t.Errorf("Source.AnyOf[2].Kind() = %q, want field_access", p.Source.AnyOf[2].Kind())
	}
	if p.Guard.AnyOf[1].HasDecorator != "@redacted" {
		t.Errorf("Guard.AnyOf[1].HasDecorator = %q", p.Guard.AnyOf[1].HasDecorator)
	}
}

func TestLoad_FixDefaultsToIdiomatic(t *testing.T) {
	body := `
id: t
severity: error
languages: [python]
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
fix:
  suggestion: "Insert {guard} before {sink.callee}."
`
	p, err := Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Fix == nil {
		t.Fatal("Fix nil")
	}
	if p.Fix.Level != FixIdiomatic {
		t.Errorf("Level = %q, want idiomatic", p.Fix.Level)
	}
	if p.Fix.Suggestion == "" {
		t.Error("Suggestion empty")
	}
}

func TestLoad_FixRejectsBadLevel(t *testing.T) {
	body := `
id: t
severity: error
languages: [python]
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
fix:
  level: aggressive
  suggestion: "x"
`
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "fix.level") {
		t.Fatalf("expected fix.level error, got %v", err)
	}
}

func TestLoad_FixRequiresSuggestion(t *testing.T) {
	body := `
id: t
severity: error
languages: [python]
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
fix:
  level: idiomatic
`
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "fix.suggestion") {
		t.Fatalf("expected fix.suggestion error, got %v", err)
	}
}

func TestParse_Errors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "missing id",
			yaml:    minimal(""),
			wantSub: "id: required",
		},
		{
			name:    "bad id chars",
			yaml:    minimal("BadID"),
			wantSub: "must match",
		},
		{
			name: "bad severity",
			yaml: `
id: x
severity: catastrophic
languages: [python]
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
`,
			wantSub: "severity",
		},
		{
			name: "no languages",
			yaml: `
id: x
severity: error
languages: []
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
`,
			wantSub: "languages",
		},
		{
			name: "unknown language",
			yaml: `
id: x
severity: error
languages: [cobol]
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
`,
			wantSub: "supported language",
		},
		{
			name: "empty source",
			yaml: `
id: x
severity: error
languages: [python]
source: {any_of: []}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
`,
			wantSub: "source.any_of",
		},
		{
			name: "predicate two kinds",
			yaml: `
id: x
severity: error
languages: [python]
source: {any_of: [{calls: a, has_decorator: "@b"}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
`,
			wantSub: "exactly one matcher",
		},
		{
			name: "predicate empty",
			yaml: `
id: x
severity: error
languages: [python]
source: {any_of: [{}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
`,
			wantSub: "predicate is empty",
		},
		{
			name: "missing message",
			yaml: `
id: x
severity: error
languages: [python]
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
`,
			wantSub: "message",
		},
		{
			name: "unknown field",
			yaml: `
id: x
severity: error
languages: [python]
extras: nope
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
`,
			wantSub: "extras",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatalf("Parse: expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Parse error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestPredicate_KindAndValue(t *testing.T) {
	p := Predicate{Calls: "x.y"}
	if p.Kind() != "calls" || p.Value() != "x.y" {
		t.Errorf("calls predicate: kind=%q value=%q", p.Kind(), p.Value())
	}
	p = Predicate{HasDecorator: "@auth"}
	if p.Kind() != "has_decorator" || p.Value() != "@auth" {
		t.Errorf("decorator predicate: kind=%q value=%q", p.Kind(), p.Value())
	}
	p = Predicate{}
	if p.Kind() != "" || p.Value() != "" {
		t.Errorf("empty predicate: kind=%q value=%q", p.Kind(), p.Value())
	}
}

func minimal(id string) string {
	return `
id: ` + id + `
severity: error
languages: [python]
source: {any_of: [{calls: a}]}
sink: {any_of: [{calls: b}]}
guard: {any_of: [{calls: c}]}
message: m
`
}
