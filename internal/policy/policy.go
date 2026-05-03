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
}

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
	if p.ID == "" {
		return errors.New("id: required")
	}
	if !idPattern.MatchString(p.ID) {
		return fmt.Errorf("id: %q must match %s", p.ID, idPattern)
	}
	switch p.Severity {
	case SeverityError, SeverityWarning, SeverityInfo:
	case "":
		return errors.New("severity: required (error|warning|info)")
	default:
		return fmt.Errorf("severity: %q must be error|warning|info", p.Severity)
	}
	if len(p.Languages) == 0 {
		return errors.New("languages: at least one required")
	}
	for _, lang := range p.Languages {
		switch lang {
		case LangPython, LangTypeScript, LangGo, LangJava:
		default:
			return fmt.Errorf("languages: %q is not a supported language", lang)
		}
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
