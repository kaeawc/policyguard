// Package engine is the reachability solver. Given a call graph and a
// policy, it produces findings for every function that violates the
// source -> guard -> sink contract.
//
// MVP scope (intra-procedural):
//
//	A violation is a function F such that:
//	  * F contains a source-matching call site, AND
//	  * F contains a sink-matching call site, AND
//	  * F contains no guard-matching call site or decorator.
//
// Interprocedural extension (call F -> G with the sink in G) is a
// follow-up. Documented as TODO at the boundary so callers know not to
// rely on transitive reachability yet.
package engine

import (
	"sort"
	"strings"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/policy"
)

// Finding describes a single policy violation.
type Finding struct {
	PolicyID string
	Severity policy.Severity
	Message  string

	// Function is the FQN of the function containing the violation, or
	// "<module>" when the offending sites are at module scope.
	Function callgraph.FQN

	// Source and Sink point at the offending call sites.
	Source FindingSite
	Sink   FindingSite
}

// FindingSite is one endpoint of a violation.
type FindingSite struct {
	Callee callgraph.FQN
	Path   string
	Line   int
}

// Analyze runs one policy over the call graph and returns any violations,
// sorted deterministically by function FQN then source line.
func Analyze(g *callgraph.Graph, p *policy.Policy) []Finding {
	var out []Finding
	// Iterate every caller (functions and module scope).
	for caller, sites := range g.Calls {
		hasGuard := matcherMatchesAny(p.Guard, sites) || functionHasGuardDecorator(g, caller, p.Guard)
		if hasGuard {
			continue
		}
		var sources, sinks []*callgraph.CallSite
		for _, site := range sites {
			if matcherMatches(p.Source, site) {
				sources = append(sources, site)
			}
			if matcherMatches(p.Sink, site) {
				sinks = append(sinks, site)
			}
		}
		if len(sources) == 0 || len(sinks) == 0 {
			continue
		}
		// One finding per (source, sink) pair within this function. For
		// MVP we report only the first pair to keep noise down; full
		// pairing is a follow-up.
		out = append(out, Finding{
			PolicyID: p.ID,
			Severity: p.Severity,
			Message:  p.Message,
			Function: displayCaller(caller),
			Source:   siteOf(sources[0]),
			Sink:     siteOf(sinks[0]),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Function != out[j].Function {
			return out[i].Function < out[j].Function
		}
		return out[i].Source.Line < out[j].Source.Line
	})
	return out
}

func displayCaller(c callgraph.FQN) callgraph.FQN {
	if c == "" {
		return "<module>"
	}
	return c
}

func siteOf(c *callgraph.CallSite) FindingSite {
	return FindingSite{
		Callee: c.Callee,
		Path:   c.File.Path,
		Line:   c.Line,
	}
}

// matcherMatchesAny reports whether at least one site in sites matches m.
func matcherMatchesAny(m policy.Matcher, sites []*callgraph.CallSite) bool {
	for _, s := range sites {
		if matcherMatches(m, s) {
			return true
		}
	}
	return false
}

// matcherMatches reports whether the matcher's any_of disjunction matches
// the given call site.
func matcherMatches(m policy.Matcher, site *callgraph.CallSite) bool {
	for _, pred := range m.AnyOf {
		if predicateMatchesSite(pred, site) {
			return true
		}
	}
	return false
}

// predicateMatchesSite is true if pred matches site. MVP supports only the
// `calls` predicate (with optional trailing `.*` wildcard). `has_decorator`
// and `field_access` always return false here; decorators are handled
// separately at function granularity, and field_access is not yet wired.
func predicateMatchesSite(pred policy.Predicate, site *callgraph.CallSite) bool {
	switch pred.Kind() {
	case "calls":
		return callsMatches(pred.Calls, site)
	case "has_decorator", "field_access":
		return false
	default:
		return false
	}
}

// callsMatches matches a callee FQN against a pattern. A pattern ending
// in `.*` matches any callee with that prefix; otherwise an exact match.
func callsMatches(pattern string, site *callgraph.CallSite) bool {
	callee := string(site.Callee)
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		return callee == prefix || strings.HasPrefix(callee, prefix+".")
	}
	if callee == pattern {
		return true
	}
	// Also try the unresolved raw text — useful when the import map could
	// not resolve the callee but the policy uses the project-relative name.
	return site.Raw == pattern
}

// functionHasGuardDecorator reports whether the function with the given
// FQN has a decorator matching one of m's has_decorator predicates.
//
// TODO: decorators are not yet extracted by the call graph builder; this
// always returns false. Once decorators are tracked on FuncNode, wire
// them through here.
func functionHasGuardDecorator(g *callgraph.Graph, _ callgraph.FQN, m policy.Matcher) bool {
	_ = g
	_ = m
	return false
}
