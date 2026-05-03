// Package output renders engine findings into human-readable text, JSON,
// or SARIF 2.1.0 (for GitHub code scanning, IDE integrations, etc.).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/engine"
	"github.com/kaeawc/policyguard/internal/policy"
)

// Format selects which renderer Render uses.
type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatMarkdown Format = "markdown"
)

// Args bundles everything any renderer might need. Each format reads only
// the fields it cares about.
type Args struct {
	Findings []engine.Finding
	// Policies were loaded by the CLI; SARIF uses them to populate the
	// tool's rules array. Other formats ignore.
	Policies []*policy.Policy
	// Version is the policyguard build version, surfaced in SARIF.
	Version string
}

// Render writes args.Findings to w in the chosen format. Unknown formats
// return an error rather than falling back silently.
func Render(w io.Writer, format Format, args Args) error {
	switch format {
	case FormatText, "":
		return renderText(w, args)
	case FormatJSON:
		return renderJSON(w, args)
	case FormatSARIF:
		return renderSARIF(w, args)
	case FormatMarkdown:
		return renderMarkdown(w, args)
	default:
		return fmt.Errorf("unknown output format: %q", format)
	}
}

// ---------------------------------------------------------------- text

func renderText(w io.Writer, args Args) error {
	if len(args.Findings) == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
	}
	for _, f := range args.Findings {
		if _, err := fmt.Fprintf(w, "%s:%d: [%s] %s: %s -> %s\n  in %s; sink at %s:%d\n",
			f.Source.Path, f.Source.Line,
			f.Severity, f.PolicyID,
			f.Source.Callee, f.Sink.Callee,
			f.Function, f.Sink.Path, f.Sink.Line); err != nil {
			return err
		}
		if isInterprocedural(f.SourceChain) {
			fmt.Fprintf(w, "  source path: %s\n", joinChain(f.SourceChain))
		}
		if isInterprocedural(f.SinkChain) {
			fmt.Fprintf(w, "  sink path:   %s\n", joinChain(f.SinkChain))
		}
	}
	_, err := fmt.Fprintf(w, "\n%d finding(s)\n", len(args.Findings))
	return err
}

// isInterprocedural reports whether the chain spans more than one
// function (a chain of length 1 is just the violator itself, which
// doesn't add information).
func isInterprocedural(chain []callgraph.FQN) bool {
	return len(chain) > 1
}

// chainStrings flattens a chain to []string. Returns nil for chains
// that are intra-procedural (length <= 1) so the JSON omits the field
// entirely.
func chainStrings(chain []callgraph.FQN) []string {
	if !isInterprocedural(chain) {
		return nil
	}
	out := make([]string, len(chain))
	for i, c := range chain {
		out[i] = string(c)
	}
	return out
}

func joinChain(chain []callgraph.FQN) string {
	parts := make([]string, len(chain))
	for i, c := range chain {
		parts[i] = string(c)
	}
	return strings.Join(parts, " -> ")
}

// ------------------------------------------------------------ markdown

// renderMarkdown emits a PR-comment-friendly summary. Layout:
//
//	## policyguard
//	No policy violations found. ✓
//
// Or, with findings:
//
//	## policyguard — N finding(s)
//
//	**[error]** `pii-redaction-before-llm` in `app.handlers.fetch_summary`
//	> User PII reaches LLM call without passing through redactor.
//	- source: [app/handlers.py:7](app/handlers.py#L7) — `app.handlers.load_user`
//	- sink:   [app/handlers.py:15](app/handlers.py#L15) — `anthropic.messages.create`
//
//	---
//	(more findings…)
//
// Findings are kept in the order Analyze produced (sorted by function
// FQN then source line) so the rendering is stable across runs.
func renderMarkdown(w io.Writer, args Args) error {
	if len(args.Findings) == 0 {
		_, err := fmt.Fprintln(w, "## policyguard\nNo policy violations found.")
		return err
	}
	if _, err := fmt.Fprintf(w, "## policyguard — %d finding(s)\n\n", len(args.Findings)); err != nil {
		return err
	}
	for i, f := range args.Findings {
		if i > 0 {
			if _, err := fmt.Fprintln(w, "\n---"); err != nil {
				return err
			}
		}
		if err := renderMarkdownFinding(w, f); err != nil {
			return err
		}
	}
	return nil
}

func renderMarkdownFinding(w io.Writer, f engine.Finding) error {
	if _, err := fmt.Fprintf(w, "**[%s]** `%s` in `%s`\n",
		f.Severity, f.PolicyID, f.Function); err != nil {
		return err
	}
	if f.Message != "" {
		if _, err := fmt.Fprintf(w, "> %s\n\n", f.Message); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "- source: [%s:%d](%s#L%d) — `%s`\n",
		f.Source.Path, f.Source.Line, f.Source.Path, f.Source.Line, f.Source.Callee); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "- sink: [%s:%d](%s#L%d) — `%s`\n",
		f.Sink.Path, f.Sink.Line, f.Sink.Path, f.Sink.Line, f.Sink.Callee); err != nil {
		return err
	}
	if isInterprocedural(f.SourceChain) {
		if _, err := fmt.Fprintf(w, "- source path: `%s`\n", joinChain(f.SourceChain)); err != nil {
			return err
		}
	}
	if isInterprocedural(f.SinkChain) {
		if _, err := fmt.Fprintf(w, "- sink path: `%s`\n", joinChain(f.SinkChain)); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- json

// jsonFinding is the wire shape — independent of engine internals so
// downstream consumers don't break when we refactor.
type jsonFinding struct {
	PolicyID    string          `json:"policy_id"`
	Severity    policy.Severity `json:"severity"`
	Message     string          `json:"message"`
	Function    string          `json:"function"`
	Source      jsonSite        `json:"source"`
	Sink        jsonSite        `json:"sink"`
	SourceChain []string        `json:"source_chain,omitempty"`
	SinkChain   []string        `json:"sink_chain,omitempty"`
}

type jsonSite struct {
	Callee string `json:"callee"`
	Path   string `json:"path"`
	Line   int    `json:"line"`
}

func renderJSON(w io.Writer, args Args) error {
	out := make([]jsonFinding, 0, len(args.Findings))
	for _, f := range args.Findings {
		out = append(out, jsonFinding{
			PolicyID: f.PolicyID,
			Severity: f.Severity,
			Message:  f.Message,
			Function: string(f.Function),
			Source: jsonSite{
				Callee: string(f.Source.Callee),
				Path:   f.Source.Path,
				Line:   f.Source.Line,
			},
			Sink: jsonSite{
				Callee: string(f.Sink.Callee),
				Path:   f.Sink.Path,
				Line:   f.Sink.Line,
			},
			SourceChain: chainStrings(f.SourceChain),
			SinkChain:   chainStrings(f.SinkChain),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --------------------------------------------------------------- sarif

// SARIF 2.1.0 minimal subset. Only the fields policyguard actually
// populates — third-party readers (GitHub code scanning, VS Code SARIF
// viewer) tolerate omitted optional fields.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	ShortDescription     sarifMessage           `json:"shortDescription"`
	DefaultConfiguration sarifRuleConfiguration `json:"defaultConfiguration"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID           string          `json:"ruleId"`
	Level            string          `json:"level"`
	Message          sarifMessage    `json:"message"`
	Locations        []sarifLocation `json:"locations"`
	RelatedLocations []sarifLocation `json:"relatedLocations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifMessage         `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func renderSARIF(w io.Writer, args Args) error {
	rules := buildSARIFRules(args.Policies, args.Findings)
	results := make([]sarifResult, 0, len(args.Findings))
	for _, f := range args.Findings {
		results = append(results, sarifResult{
			RuleID:  f.PolicyID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Source.Path},
					Region:           sarifRegion{StartLine: f.Source.Line},
				},
				Message: &sarifMessage{Text: "source: " + string(f.Source.Callee)},
			}},
			RelatedLocations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Sink.Path},
					Region:           sarifRegion{StartLine: f.Sink.Line},
				},
				Message: &sarifMessage{Text: "sink: " + string(f.Sink.Callee)},
			}},
		})
	}
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "policyguard",
				Version:        firstNonEmpty(args.Version, "dev"),
				InformationURI: "https://github.com/kaeawc/policyguard",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// buildSARIFRules synthesizes the rules array. Prefers loaded policies
// (so rules show up even when no findings fired); falls back to deriving
// them from the findings themselves.
func buildSARIFRules(policies []*policy.Policy, findings []engine.Finding) []sarifRule {
	seen := make(map[string]bool)
	var out []sarifRule
	for _, p := range policies {
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		out = append(out, sarifRule{
			ID:                   p.ID,
			ShortDescription:     sarifMessage{Text: p.Message},
			DefaultConfiguration: sarifRuleConfiguration{Level: sarifLevel(p.Severity)},
		})
	}
	for _, f := range findings {
		if seen[f.PolicyID] {
			continue
		}
		seen[f.PolicyID] = true
		out = append(out, sarifRule{
			ID:                   f.PolicyID,
			ShortDescription:     sarifMessage{Text: f.Message},
			DefaultConfiguration: sarifRuleConfiguration{Level: sarifLevel(f.Severity)},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sarifLevel(s policy.Severity) string {
	switch s {
	case policy.SeverityError:
		return "error"
	case policy.SeverityWarning:
		return "warning"
	case policy.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
