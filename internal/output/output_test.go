package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/engine"
	"github.com/kaeawc/policyguard/internal/policy"
)

func sampleFindings() []engine.Finding {
	return []engine.Finding{{
		PolicyID: "pii-redaction-before-llm",
		Severity: policy.SeverityError,
		Message:  "User PII reaches LLM call.",
		Function: callgraph.FQN("svc.handler.fetch"),
		Source: engine.FindingSite{
			Callee: callgraph.FQN("user_repo.get_user"),
			Path:   "svc/handler.py",
			Line:   2,
		},
		Sink: engine.FindingSite{
			Callee: callgraph.FQN("anthropic.messages.create"),
			Path:   "svc/handler.py",
			Line:   3,
		},
	}}
}

func samplePolicies() []*policy.Policy {
	return []*policy.Policy{{
		ID:        "pii-redaction-before-llm",
		Severity:  policy.SeverityError,
		Languages: []policy.Language{policy.LangPython},
		Source:    policy.Matcher{AnyOf: []policy.Predicate{{Calls: "user_repo.get_user"}}},
		Sink:      policy.Matcher{AnyOf: []policy.Predicate{{Calls: "anthropic.messages.create"}}},
		Guard:     policy.Matcher{AnyOf: []policy.Predicate{{Calls: "redactor.redact"}}},
		Message:   "User PII reaches LLM call.",
	}}
}

func TestRender_TextEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatText, Args{}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "no findings") {
		t.Errorf("got %q", got)
	}
}

func TestRender_TextWithFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatText, Args{Findings: sampleFindings()}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"svc/handler.py:2:",
		"[error]",
		"pii-redaction-before-llm",
		"user_repo.get_user -> anthropic.messages.create",
		"in svc.handler.fetch",
		"sink at svc/handler.py:3",
		"1 finding(s)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text output missing %q\nhad:\n%s", want, got)
		}
	}
}

func TestRender_JSONStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, Args{Findings: sampleFindings()}); err != nil {
		t.Fatal(err)
	}
	var got []jsonFinding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d", len(got))
	}
	f := got[0]
	if f.PolicyID != "pii-redaction-before-llm" || f.Severity != policy.SeverityError {
		t.Errorf("unexpected fields: %+v", f)
	}
	if f.Source.Path != "svc/handler.py" || f.Source.Line != 2 {
		t.Errorf("unexpected source: %+v", f.Source)
	}
	if f.Sink.Callee != "anthropic.messages.create" || f.Sink.Line != 3 {
		t.Errorf("unexpected sink: %+v", f.Sink)
	}
}

func TestRender_JSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, Args{}); err != nil {
		t.Fatal(err)
	}
	var got []jsonFinding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

func TestRender_SARIFStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatSARIF, Args{
		Findings: sampleFindings(),
		Policies: samplePolicies(),
		Version:  "v1.2.3",
	}); err != nil {
		t.Fatal(err)
	}
	var got sarifLog
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.Version != "2.1.0" {
		t.Errorf("Version = %q", got.Version)
	}
	if len(got.Runs) != 1 {
		t.Fatalf("Runs = %d", len(got.Runs))
	}
	run := got.Runs[0]
	if run.Tool.Driver.Name != "policyguard" || run.Tool.Driver.Version != "v1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("Rules = %d, want 1", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "pii-redaction-before-llm" {
		t.Errorf("Rules[0].ID = %q", run.Tool.Driver.Rules[0].ID)
	}
	if len(run.Results) != 1 {
		t.Fatalf("Results = %d", len(run.Results))
	}
	r := run.Results[0]
	if r.RuleID != "pii-redaction-before-llm" || r.Level != "error" {
		t.Errorf("result = %+v", r)
	}
	if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.Region.StartLine != 2 {
		t.Errorf("source location wrong: %+v", r.Locations)
	}
	if len(r.RelatedLocations) != 1 || r.RelatedLocations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Errorf("sink (related) location wrong: %+v", r.RelatedLocations)
	}
}

func TestRender_SARIFFallsBackToFindingsForRules(t *testing.T) {
	var buf bytes.Buffer
	// No policies passed in — the renderer must synthesize rules from the
	// findings themselves so the output still validates.
	if err := Render(&buf, FormatSARIF, Args{Findings: sampleFindings()}); err != nil {
		t.Fatal(err)
	}
	var got sarifLog
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 synthesized rule")
	}
}

func interproceduralFinding() engine.Finding {
	f := sampleFindings()[0]
	f.Function = callgraph.FQN("svc.handler.fetch")
	f.SourceChain = []engine.ChainHop{
		{Function: "svc.handler.fetch", Path: "svc/handler.py", Line: 5},
		{Function: "svc.handler.get_user"},
	}
	f.SinkChain = []engine.ChainHop{
		{Function: "svc.handler.fetch", Path: "svc/handler.py", Line: 6},
		{Function: "svc.handler.call_llm"},
	}
	return f
}

func TestRender_TextShowsChainForInterprocedural(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatText, Args{Findings: []engine.Finding{interproceduralFinding()}}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"source path: svc.handler.fetch (svc/handler.py:5) -> svc.handler.get_user",
		"sink path:   svc.handler.fetch (svc/handler.py:6) -> svc.handler.call_llm",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text missing %q\nhad:\n%s", want, got)
		}
	}
}

func TestRender_TextOmitsChainForIntra(t *testing.T) {
	f := sampleFindings()[0]
	f.SourceChain = []engine.ChainHop{{Function: f.Function}}
	f.SinkChain = []engine.ChainHop{{Function: f.Function}}

	var buf bytes.Buffer
	if err := Render(&buf, FormatText, Args{Findings: []engine.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "source path:") {
		t.Errorf("intra-procedural finding should not render a chain line\nhad:\n%s", buf.String())
	}
}

func TestRender_MarkdownShowsChainForInterprocedural(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatMarkdown, Args{Findings: []engine.Finding{interproceduralFinding()}}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"source path: `svc.handler.fetch` ([svc/handler.py:5](svc/handler.py#L5)) → `svc.handler.get_user`",
		"sink path: `svc.handler.fetch` ([svc/handler.py:6](svc/handler.py#L6)) → `svc.handler.call_llm`",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown missing %q\nhad:\n%s", want, got)
		}
	}
}

func TestRender_JSONIncludesChainsForInterprocedural(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, Args{Findings: []engine.Finding{interproceduralFinding()}}); err != nil {
		t.Fatal(err)
	}
	var got []jsonFinding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].SourceChain) != 2 || len(got[0].SinkChain) != 2 {
		t.Fatalf("got = %+v", got)
	}
	if got[0].SourceChain[0].Function != "svc.handler.fetch" || got[0].SourceChain[0].Line != 5 {
		t.Errorf("SourceChain[0] = %+v", got[0].SourceChain[0])
	}
	if got[0].SourceChain[1].Function != "svc.handler.get_user" {
		t.Errorf("SourceChain[1] = %+v", got[0].SourceChain[1])
	}
}

func TestRender_MarkdownEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatMarkdown, Args{}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{"## policyguard", "No policy violations found"} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown empty output missing %q\nhad:\n%s", want, got)
		}
	}
}

func TestRender_MarkdownWithFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatMarkdown, Args{Findings: sampleFindings()}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"## policyguard — 1 finding(s)",
		"**[error]** `pii-redaction-before-llm` in `svc.handler.fetch`",
		"> User PII reaches LLM call.",
		"[svc/handler.py:2](svc/handler.py#L2)",
		"`user_repo.get_user`",
		"[svc/handler.py:3](svc/handler.py#L3)",
		"`anthropic.messages.create`",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown output missing %q\nhad:\n%s", want, got)
		}
	}
}

func TestRender_MarkdownMultipleFindingsSeparator(t *testing.T) {
	findings := []engine.Finding{sampleFindings()[0], sampleFindings()[0]}
	findings[1].PolicyID = "second-rule"
	var buf bytes.Buffer
	if err := Render(&buf, FormatMarkdown, Args{Findings: findings}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "\n---\n") {
		t.Errorf("expected separator between findings\nhad:\n%s", got)
	}
	if !strings.Contains(got, "second-rule") {
		t.Errorf("missing second finding\nhad:\n%s", got)
	}
}

func TestRender_TextShowsFix(t *testing.T) {
	f := sampleFindings()[0]
	f.Fix = &engine.FindingFix{
		Level:      policy.FixIdiomatic,
		Suggestion: "Wrap the user object in redactor.redact.",
	}
	var buf bytes.Buffer
	if err := Render(&buf, FormatText, Args{Findings: []engine.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "fix [idiomatic]: Wrap the user object in redactor.redact.") {
		t.Errorf("text missing fix line\nhad:\n%s", buf.String())
	}
}

func TestRender_MarkdownShowsFix(t *testing.T) {
	f := sampleFindings()[0]
	f.Fix = &engine.FindingFix{
		Level:      policy.FixIdiomatic,
		Suggestion: "Wrap user in redactor.redact.",
	}
	var buf bytes.Buffer
	if err := Render(&buf, FormatMarkdown, Args{Findings: []engine.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "- fix _(idiomatic)_: Wrap user in redactor.redact.") {
		t.Errorf("markdown missing fix bullet\nhad:\n%s", buf.String())
	}
}

func TestRender_JSONIncludesFix(t *testing.T) {
	f := sampleFindings()[0]
	f.Fix = &engine.FindingFix{Level: policy.FixIdiomatic, Suggestion: "x"}
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, Args{Findings: []engine.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	var got []jsonFinding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Fix == nil || got[0].Fix.Suggestion != "x" {
		t.Errorf("got = %+v", got)
	}
}

func TestRender_MarkdownShowsPatchDiff(t *testing.T) {
	f := sampleFindings()[0]
	f.Fix = &engine.FindingFix{
		Level:      policy.FixIdiomatic,
		Suggestion: "wrap it",
		Patch: &engine.FindingPatch{
			Path:    "x.py",
			Line:    5,
			OldLine: "    f(user)",
			NewLine: "    f(redactor.redact(user))",
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, FormatMarkdown, Args{Findings: []engine.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"```diff",
		"-    f(user)",
		"+    f(redactor.redact(user))",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown missing %q\nhad:\n%s", want, got)
		}
	}
}

func TestRender_JSONIncludesPatch(t *testing.T) {
	f := sampleFindings()[0]
	f.Fix = &engine.FindingFix{
		Level:      policy.FixIdiomatic,
		Suggestion: "x",
		Patch: &engine.FindingPatch{
			Path:    "x.py",
			Line:    5,
			OldLine: "f(u)",
			NewLine: "f(r(u))",
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, Args{Findings: []engine.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	var got []jsonFinding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got[0].Fix.Patch == nil || got[0].Fix.Patch.NewLine != "f(r(u))" {
		t.Errorf("Patch = %+v", got[0].Fix.Patch)
	}
	if !strings.Contains(got[0].Fix.Patch.UnifiedDiff, "+f(r(u))") {
		t.Errorf("UnifiedDiff missing +line: %q", got[0].Fix.Patch.UnifiedDiff)
	}
}

func TestRender_SARIFIncludesFix(t *testing.T) {
	f := sampleFindings()[0]
	f.Fix = &engine.FindingFix{Level: policy.FixIdiomatic, Suggestion: "do x"}
	var buf bytes.Buffer
	if err := Render(&buf, FormatSARIF, Args{Findings: []engine.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs[0].Results) != 1 || len(log.Runs[0].Results[0].Fixes) != 1 {
		t.Fatalf("expected one fix, got %+v", log.Runs[0].Results)
	}
	if log.Runs[0].Results[0].Fixes[0].Description.Text != "do x" {
		t.Errorf("Fixes[0].Description = %+v", log.Runs[0].Results[0].Fixes[0].Description)
	}
}

func TestRender_UnknownFormatErrors(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, Format("xml"), Args{})
	if err == nil || !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("expected unknown-format error, got %v", err)
	}
}

func TestRender_SARIFLevelMapping(t *testing.T) {
	tests := []struct {
		sev  policy.Severity
		want string
	}{
		{policy.SeverityError, "error"},
		{policy.SeverityWarning, "warning"},
		{policy.SeverityInfo, "note"},
	}
	for _, tc := range tests {
		if got := sarifLevel(tc.sev); got != tc.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tc.sev, got, tc.want)
		}
	}
}
