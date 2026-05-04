// Package policy loads and validates policyguard policy YAML files.
//
// A policy declares a source/guard/sink contract: every codepath from any
// matching source to any matching sink must pass through at least one
// matching guard. The loader's job is parsing + validation; the engine
// (separate package) consumes a *Policy.
package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity is how a violation should be reported.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Language identifiers supported by the policy schema. Engines may support
// a subset; a policy with `languages: [python, go]` only runs on those.
type Language string

const (
	LangPython     Language = "python"
	LangTypeScript Language = "typescript"
	LangGo         Language = "go"
	LangJava       Language = "java"
)

// Policy is a single source/guard/sink contract.
type Policy struct {
	ID        string     `yaml:"id"`
	Severity  Severity   `yaml:"severity"`
	Languages []Language `yaml:"languages"`
	Source    Matcher    `yaml:"source"`
	Sink      Matcher    `yaml:"sink"`
	Guard     Matcher    `yaml:"guard"`
	Message   string     `yaml:"message"`
	Fix       *Fix       `yaml:"fix,omitempty"`
}

// Fix is an optional autofix descriptor. The suggestion is a text
// template that the engine renders into each Finding using simple
// `{placeholder}` substitution. Supported placeholders:
//
//	{policy.id}
//	{function}
//	{source.callee}, {source.path}, {source.line}
//	{sink.callee}, {sink.path}, {sink.line}
//	{guard}   — first guard predicate's value, prefixed `@` for
//	            has_decorator predicates; empty if guard has no
//	            predicates.
//
// When WrapArgument is set, the engine attempts to produce a structured
// patch: it locates the sink call site's Nth positional argument and
// rewrites it to `{guard}(<original-arg>)`. The guard call name comes
// from the first `calls` predicate in the policy's guard matcher.
type Fix struct {
	// Level is the autofix safety tier. Defaults to "idiomatic".
	// Future: "cosmetic" (whitespace-only) and "semantic" (behavior-
	// changing, opt-in) are reserved.
	Level FixLevel `yaml:"level,omitempty"`
	// Suggestion is the human-readable fix proposal. Required.
	Suggestion string `yaml:"suggestion"`
	// WrapArgument, when non-nil, instructs the engine to produce a
	// structured patch wrapping the sink call's Nth positional argument
	// with the policy's guard call. Zero-based; nil means no patch.
	WrapArgument *int `yaml:"wrap_argument,omitempty"`
}

// FixLevel indicates how disruptive the fix is.
type FixLevel string

const (
	FixIdiomatic FixLevel = "idiomatic"
	FixCosmetic  FixLevel = "cosmetic"
	FixSemantic  FixLevel = "semantic"
)

// Matcher is a disjunction of predicates. The MVP only supports any_of;
// future versions may add all_of and not.
type Matcher struct {
	AnyOf []Predicate `yaml:"any_of"`
}

// Predicate is one structural condition. Exactly one field must be set.
//
// Supported kinds:
//   - Calls:        callee FQN to match (supports trailing `.*` wildcard).
//   - HasDecorator: decorator name to match (Python `@decorator` syntax).
//   - FieldAccess:  attribute access pattern, e.g. `*.email`.
type Predicate struct {
	Calls        string `yaml:"calls,omitempty"`
	HasDecorator string `yaml:"has_decorator,omitempty"`
	FieldAccess  string `yaml:"field_access,omitempty"`
}

// Kind returns a short identifier for which matcher field is set, or "" if
// the predicate is empty (an error condition caught by Validate).
func (p Predicate) Kind() string {
	switch {
	case p.Calls != "":
		return "calls"
	case p.HasDecorator != "":
		return "has_decorator"
	case p.FieldAccess != "":
		return "field_access"
	default:
		return ""
	}
}

// Value returns the matcher's argument string, or "" if empty.
func (p Predicate) Value() string {
	switch p.Kind() {
	case "calls":
		return p.Calls
	case "has_decorator":
		return p.HasDecorator
	case "field_access":
		return p.FieldAccess
	default:
		return ""
	}
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Load parses and validates a policy from a YAML file.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return p, nil
}

// LoadDir loads every `*.yaml` and `*.yml` file under root (non-recursive)
// as a policy. Files are loaded in lexical order so callers see a stable
// policy ordering.
func LoadDir(root string) ([]*Policy, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", root, err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		paths = append(paths, filepath.Join(root, name))
	}
	sort.Strings(paths)
	out := make([]*Policy, 0, len(paths))
	seen := make(map[string]string, len(paths))
	for _, path := range paths {
		p, err := Load(path)
		if err != nil {
			return nil, err
		}
		if prev, ok := seen[p.ID]; ok {
			return nil, fmt.Errorf("duplicate policy id %q in %s and %s", p.ID, prev, path)
		}
		seen[p.ID] = path
		out = append(out, p)
	}
	return out, nil
}

// Parse reads YAML from r and validates the resulting policy.
func Parse(r io.Reader) (*Policy, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty policy document")
		}
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate returns the first structural error in the policy, or nil if it
// is well-formed.
func (p *Policy) Validate() error {
	if err := validateIDAndSeverity(p); err != nil {
		return err
	}
	if err := validateLanguages(p.Languages); err != nil {
		return err
	}
	if err := validateMatcher("source", p.Source); err != nil {
		return err
	}
	if err := validateMatcher("sink", p.Sink); err != nil {
		return err
	}
	if err := validateMatcher("guard", p.Guard); err != nil {
		return err
	}
	if p.Message == "" {
		return errors.New("message: required")
	}
	if p.Fix != nil {
		return validateFix(p.Fix)
	}
	return nil
}

func validateIDAndSeverity(p *Policy) error {
	if p.ID == "" {
		return errors.New("id: required")
	}
	if !idPattern.MatchString(p.ID) {
		return fmt.Errorf("id: %q must match %s", p.ID, idPattern)
	}
	switch p.Severity {
	case SeverityError, SeverityWarning, SeverityInfo:
		return nil
	case "":
		return errors.New("severity: required (error|warning|info)")
	default:
		return fmt.Errorf("severity: %q must be error|warning|info", p.Severity)
	}
}

func validateLanguages(langs []Language) error {
	if len(langs) == 0 {
		return errors.New("languages: at least one required")
	}
	for _, lang := range langs {
		switch lang {
		case LangPython, LangTypeScript, LangGo, LangJava:
		default:
			return fmt.Errorf("languages: %q is not a supported language", lang)
		}
	}
	return nil
}

func validateFix(f *Fix) error {
	if f.Suggestion == "" {
		return errors.New("fix.suggestion: required when fix is set")
	}
	switch f.Level {
	case "":
		f.Level = FixIdiomatic
	case FixCosmetic, FixIdiomatic, FixSemantic:
	default:
		return fmt.Errorf("fix.level: %q must be cosmetic|idiomatic|semantic", f.Level)
	}
	if f.WrapArgument != nil && *f.WrapArgument < 0 {
		return fmt.Errorf("fix.wrap_argument: %d must be >= 0", *f.WrapArgument)
	}
	return nil
}

func validateMatcher(field string, m Matcher) error {
	if len(m.AnyOf) == 0 {
		return fmt.Errorf("%s.any_of: at least one predicate required", field)
	}
	for i, pred := range m.AnyOf {
		kinds := 0
		if pred.Calls != "" {
			kinds++
		}
		if pred.HasDecorator != "" {
			kinds++
		}
		if pred.FieldAccess != "" {
			kinds++
		}
		switch kinds {
		case 0:
			return fmt.Errorf("%s.any_of[%d]: predicate is empty", field, i)
		case 1:
			// ok
		default:
			return fmt.Errorf("%s.any_of[%d]: predicate must set exactly one matcher kind", field, i)
		}
	}
	return nil
}
