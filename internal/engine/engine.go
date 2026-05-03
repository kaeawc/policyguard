// Package engine is the reachability solver. Given a call graph and a
// policy, it produces findings for every function that violates the
// source -> guard -> sink contract.
//
// Detection model (closure-based interprocedural):
//
//	For each internal function F, build the closure: F plus every
//	internal function transitively reachable from F via the call graph.
//	The union of all call sites in the closure is F's "effective" call
//	site set. F violates the contract iff its effective set contains a
//	source-matching site AND a sink-matching site AND no guard-matching
//	site.
//
// This catches both intra-procedural cases (source/sink/guard in the
// same function) and interprocedural cases where, e.g., a wrapper
// function calls one helper that produces PII and another helper that
// hands it to an LLM.
//
// Module-scope code (caller == "") is analyzed intra-procedurally only;
// transitive expansion isn't meaningful at module scope.
//
// `has_decorator` and `field_access` predicates are still stubbed (the
// call-graph builder doesn't extract decorators or attribute reads yet).
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

	// Function is the FQN at which the violation is rooted. For an
	// interprocedural finding this is the smallest closure containing
	// both source and sink (the "minimal violator").
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

// Analyze runs one policy over the call graph and returns the violations,
// sorted deterministically by function FQN then source line.
func Analyze(g *callgraph.Graph, p *policy.Policy) []Finding {
	out := analyzeFunctions(g, p)
	out = append(out, analyzeModuleScope(g, p)...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Function != out[j].Function {
			return out[i].Function < out[j].Function
		}
		if out[i].Source.Path != out[j].Source.Path {
			return out[i].Source.Path < out[j].Source.Path
		}
		return out[i].Source.Line < out[j].Source.Line
	})
	return out
}

// analyzeFunctions runs the interprocedural closure check over every
// internal function in g. Findings are deduped to "minimal violators" —
// when F calls G and both their closures violate, only G is reported.
func analyzeFunctions(g *callgraph.Graph, p *policy.Policy) []Finding {
	callees := buildCalleeMap(g)
	closures := make(map[callgraph.FQN]map[callgraph.FQN]bool, len(g.Funcs))
	for fqn := range g.Funcs {
		closures[fqn] = transitiveCallees(fqn, callees)
	}

	violators := make(map[callgraph.FQN]Finding, 0)
	for fqn := range g.Funcs {
		sites := collectSites(g, closures[fqn])
		f, ok := evaluate(p, sites, fqn)
		if !ok {
			continue
		}
		violators[fqn] = f
	}

	// Minimal-violator dedup: drop F if any internal callee G in F's
	// closure is also a violator AND G has a strictly smaller closure
	// than F. The strict-subset check matters for cycles — when F and G
	// share the same closure (mutual recursion) neither is "smaller" and
	// we keep both rather than silently dropping all cycle members.
	var out []Finding
	for fqn, f := range violators {
		minimal := true
		for callee := range closures[fqn] {
			if callee == fqn {
				continue
			}
			if _, ok := violators[callee]; !ok {
				continue
			}
			if len(closures[callee]) < len(closures[fqn]) {
				minimal = false
				break
			}
		}
		if minimal {
			out = append(out, f)
		}
	}
	return out
}

// analyzeModuleScope runs the original intra-procedural check on the
// "<module>" caller bucket. Findings here are kept distinct because
// closures don't apply at module scope.
func analyzeModuleScope(g *callgraph.Graph, p *policy.Policy) []Finding {
	sites := g.Calls[""]
	if len(sites) == 0 {
		return nil
	}
	f, ok := evaluate(p, sites, "")
	if !ok {
		return nil
	}
	return []Finding{f}
}

// evaluate applies the source/guard/sink check to a call-site set. Returns
// the finding (with caller substituted for display) and whether it
// violates the policy.
func evaluate(p *policy.Policy, sites []*callgraph.CallSite, caller callgraph.FQN) (Finding, bool) {
	if matcherMatchesAny(p.Guard, sites) {
		return Finding{}, false
	}
	src := firstMatch(p.Source, sites)
	if src == nil {
		return Finding{}, false
	}
	sink := firstMatch(p.Sink, sites)
	if sink == nil {
		return Finding{}, false
	}
	return Finding{
		PolicyID: p.ID,
		Severity: p.Severity,
		Message:  p.Message,
		Function: displayCaller(caller),
		Source:   siteOf(src),
		Sink:     siteOf(sink),
	}, true
}

// buildCalleeMap inverts g.Calls into caller -> set of internal callees.
// Only callees that resolve to functions in g.Funcs are included; external
// names are call-graph leaves and don't expand the closure.
func buildCalleeMap(g *callgraph.Graph) map[callgraph.FQN][]callgraph.FQN {
	out := make(map[callgraph.FQN][]callgraph.FQN, len(g.Calls))
	seen := make(map[callgraph.FQN]map[callgraph.FQN]bool, len(g.Calls))
	for caller, sites := range g.Calls {
		if caller == "" {
			continue
		}
		for _, s := range sites {
			if _, ok := g.Funcs[s.Callee]; !ok {
				continue
			}
			if _, ok := seen[caller]; !ok {
				seen[caller] = make(map[callgraph.FQN]bool)
			}
			if seen[caller][s.Callee] {
				continue
			}
			seen[caller][s.Callee] = true
			out[caller] = append(out[caller], s.Callee)
		}
	}
	return out
}

// transitiveCallees returns the closure of start under callees, including
// start itself. Cycles are handled via the visited set.
func transitiveCallees(start callgraph.FQN, callees map[callgraph.FQN][]callgraph.FQN) map[callgraph.FQN]bool {
	visited := map[callgraph.FQN]bool{start: true}
	stack := []callgraph.FQN{start}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range callees[n] {
			if !visited[c] {
				visited[c] = true
				stack = append(stack, c)
			}
		}
	}
	return visited
}

// collectSites returns the union of call sites authored by any function
// in the closure. Stable order is achieved by sorting closure FQNs first
// and preserving each function's own site order.
func collectSites(g *callgraph.Graph, closure map[callgraph.FQN]bool) []*callgraph.CallSite {
	fqns := make([]callgraph.FQN, 0, len(closure))
	for fqn := range closure {
		fqns = append(fqns, fqn)
	}
	sort.Slice(fqns, func(i, j int) bool { return fqns[i] < fqns[j] })
	var out []*callgraph.CallSite
	for _, fqn := range fqns {
		out = append(out, g.Calls[fqn]...)
	}
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

// firstMatch returns the first call site in sites that matches m, or nil.
func firstMatch(m policy.Matcher, sites []*callgraph.CallSite) *callgraph.CallSite {
	for _, s := range sites {
		if matcherMatches(m, s) {
			return s
		}
	}
	return nil
}

// matcherMatchesAny reports whether at least one site in sites matches m.
func matcherMatchesAny(m policy.Matcher, sites []*callgraph.CallSite) bool {
	return firstMatch(m, sites) != nil
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
