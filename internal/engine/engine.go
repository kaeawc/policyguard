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
// Each finding includes the chosen source and sink endpoints plus the
// call chain (counterexample) from the violator function to the
// function whose body holds those endpoints. For intra-procedural
// findings the chain is just `[violator]`; interprocedural findings
// surface the wrapper → helper sequence so the reader can navigate the
// codepath without re-deriving it from the FQNs.
package engine

import (
	"sort"
	"strconv"
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

	// SourceChain is the call sequence from Function to the function
	// whose body holds the source site. SinkChain is the same for the
	// sink. Both start at Function and end at the containing function.
	// Intra-procedural findings have chains of length 1 ([Function]).
	// Module-scope findings (Function == "<module>") have nil chains.
	SourceChain []ChainHop
	SinkChain   []ChainHop

	// Fix is the rendered autofix suggestion attached by the policy's
	// fix template. Nil when the policy has no fix block.
	Fix *FindingFix
}

// FindingFix is the rendered autofix proposal for a finding.
type FindingFix struct {
	Level      policy.FixLevel
	Suggestion string
}

// ChainHop is one step in a counterexample chain. Function is the FQN
// at this hop. Path/Line locate the call expression where this function
// invokes the next hop in the chain — they are zero/empty for the last
// hop, which is the destination function and has no further bridge.
type ChainHop struct {
	Function callgraph.FQN
	Path     string
	Line     int
}

// FindingSite is one endpoint of a violation.
type FindingSite struct {
	Callee callgraph.FQN
	Path   string
	Line   int
}

// Analyze runs one policy over the call graph and returns the violations,
// sorted deterministically by function FQN then source line.
// Suppressed findings (those whose source or sink line is covered by a
// `policyguard: ignore <id>` annotation) are filtered out.
func Analyze(g *callgraph.Graph, p *policy.Policy) []Finding {
	out := analyzeFunctions(g, p)
	out = append(out, analyzeModuleScope(g, p)...)
	out = filterSuppressed(g, p, out)
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

// filterSuppressed removes findings whose source or sink site line is
// covered by a matching `policyguard: ignore` annotation. Both the
// source and sink locations are checked so authors can place the
// directive at either end of the violating path.
func filterSuppressed(g *callgraph.Graph, p *policy.Policy, findings []Finding) []Finding {
	out := findings[:0]
	for _, f := range findings {
		if g.MatchSuppression(f.Source.Path, f.Source.Line, p.ID) {
			continue
		}
		if g.MatchSuppression(f.Sink.Path, f.Sink.Line, p.ID) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// analyzeFunctions runs the interprocedural closure check over every
// internal function in g. Findings are deduped to "minimal violators" —
// when F calls G and both their closures violate, only G is reported.
func analyzeFunctions(g *callgraph.Graph, p *policy.Policy) []Finding {
	callees := buildCalleeMap(g)
	bridges := buildBridgeMap(g)
	closures := make(map[callgraph.FQN]map[callgraph.FQN]bool, len(g.Funcs))
	for fqn := range g.Funcs {
		closures[fqn] = transitiveCallees(fqn, callees)
	}

	violators := make(map[callgraph.FQN]Finding, 0)
	for fqn := range g.Funcs {
		sites := collectSites(g, closures[fqn])
		fields := collectFields(g, closures[fqn])
		decorators := collectDecorators(g, closures[fqn])
		f, srcCarrier, sinkCarrier, ok := evaluate(p, sites, fields, decorators, fqn)
		if !ok {
			continue
		}
		f.SourceChain = chainHops(shortestPath(fqn, srcCarrier, callees), bridges)
		f.SinkChain = chainHops(shortestPath(fqn, sinkCarrier, callees), bridges)
		f.Fix = renderFix(p, f)
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
// closures don't apply at module scope. Module scope has no decorators
// and no call chains (the violator is "<module>" itself).
func analyzeModuleScope(g *callgraph.Graph, p *policy.Policy) []Finding {
	sites := g.Calls[""]
	fields := g.Fields[""]
	if len(sites) == 0 && len(fields) == 0 {
		return nil
	}
	f, _, _, ok := evaluate(p, sites, fields, nil, "")
	if !ok {
		return nil
	}
	f.Fix = renderFix(p, f)
	return []Finding{f}
}

// renderFix renders the policy's fix template into the finding. Returns
// nil if the policy has no fix block. Substitution is a flat string
// replace over a small set of placeholders documented on policy.Fix.
func renderFix(p *policy.Policy, f Finding) *FindingFix {
	if p.Fix == nil {
		return nil
	}
	level := p.Fix.Level
	if level == "" {
		level = policy.FixIdiomatic
	}
	r := strings.NewReplacer(
		"{policy.id}", p.ID,
		"{function}", string(f.Function),
		"{source.callee}", string(f.Source.Callee),
		"{source.path}", f.Source.Path,
		"{source.line}", strconv.Itoa(f.Source.Line),
		"{sink.callee}", string(f.Sink.Callee),
		"{sink.path}", f.Sink.Path,
		"{sink.line}", strconv.Itoa(f.Sink.Line),
		"{guard}", firstGuardValue(p.Guard),
	)
	return &FindingFix{
		Level:      level,
		Suggestion: r.Replace(p.Fix.Suggestion),
	}
}

// firstGuardValue picks a representative value from the guard matcher
// for use in fix templates: first calls predicate value, otherwise
// first has_decorator value with `@` prefix, otherwise empty.
func firstGuardValue(m policy.Matcher) string {
	for _, pred := range m.AnyOf {
		switch pred.Kind() {
		case "calls":
			return pred.Calls
		case "has_decorator":
			return pred.HasDecorator
		}
	}
	return ""
}

// collectFields returns the union of field-access sites across every
// function in the closure, in stable FQN order.
func collectFields(g *callgraph.Graph, closure map[callgraph.FQN]bool) []*callgraph.FieldAccess {
	fqns := make([]callgraph.FQN, 0, len(closure))
	for fqn := range closure {
		fqns = append(fqns, fqn)
	}
	sort.Slice(fqns, func(i, j int) bool { return fqns[i] < fqns[j] })
	var out []*callgraph.FieldAccess
	for _, fqn := range fqns {
		out = append(out, g.Fields[fqn]...)
	}
	return out
}

// collectDecorators returns the union of decorator names across every
// function in the closure. Order is stable (sorted by FQN).
func collectDecorators(g *callgraph.Graph, closure map[callgraph.FQN]bool) []string {
	fqns := make([]callgraph.FQN, 0, len(closure))
	for fqn := range closure {
		fqns = append(fqns, fqn)
	}
	sort.Slice(fqns, func(i, j int) bool { return fqns[i] < fqns[j] })
	var out []string
	for _, fqn := range fqns {
		if fn, ok := g.Funcs[fqn]; ok {
			out = append(out, fn.Decorators...)
		}
	}
	return out
}

// matcherMatchesDecorators reports whether any has_decorator predicate in
// m matches any decorator name in decorators. The policy value's leading
// `@` is stripped before comparison.
func matcherMatchesDecorators(m policy.Matcher, decorators []string) bool {
	for _, pred := range m.AnyOf {
		if pred.Kind() != "has_decorator" {
			continue
		}
		want := strings.TrimPrefix(pred.HasDecorator, "@")
		for _, dec := range decorators {
			if dec == want {
				return true
			}
		}
	}
	return false
}

// evaluate applies the source/guard/sink check across all evidence kinds
// available at this scope: call sites, field-access sites, and the
// decorators present on functions in the closure. Returns the finding,
// the carrier FQNs of the matched source/sink (the function whose body
// holds each), and whether it violates the policy.
func evaluate(p *policy.Policy, sites []*callgraph.CallSite, fields []*callgraph.FieldAccess, decorators []string, caller callgraph.FQN) (Finding, callgraph.FQN, callgraph.FQN, bool) {
	if guardSatisfied(p.Guard, sites, fields, decorators) {
		return Finding{}, "", "", false
	}
	src, srcSite, srcCarrier := firstMatchAny(p.Source, sites, fields)
	if src == nil {
		return Finding{}, "", "", false
	}
	sink, sinkSite, sinkCarrier := firstMatchAny(p.Sink, sites, fields)
	if sink == nil {
		return Finding{}, "", "", false
	}
	return Finding{
		PolicyID: p.ID,
		Severity: p.Severity,
		Message:  p.Message,
		Function: displayCaller(caller),
		Source:   srcSite,
		Sink:     sinkSite,
	}, srcCarrier, sinkCarrier, true
}

// guardSatisfied reports whether the guard matcher fires against the
// given evidence (call sites, field-access reads, or decorators).
func guardSatisfied(m policy.Matcher, sites []*callgraph.CallSite, fields []*callgraph.FieldAccess, decorators []string) bool {
	if matcherMatchesDecorators(m, decorators) {
		return true
	}
	hit, _, _ := firstMatchAny(m, sites, fields)
	return hit != nil
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

// bridgeKey identifies the (caller, callee) edge in the call graph; the
// bridges map records the first call site connecting them, used to
// annotate counterexample chains with file:line per hop.
type bridgeKey struct {
	caller callgraph.FQN
	callee callgraph.FQN
}

// buildBridgeMap collapses g.Calls into (caller, callee) -> first
// CallSite. Only edges where the callee resolves to a known internal
// function are kept — those are the only edges chain BFS traverses.
func buildBridgeMap(g *callgraph.Graph) map[bridgeKey]*callgraph.CallSite {
	out := make(map[bridgeKey]*callgraph.CallSite)
	for caller, sites := range g.Calls {
		if caller == "" {
			continue
		}
		for _, s := range sites {
			if _, ok := g.Funcs[s.Callee]; !ok {
				continue
			}
			k := bridgeKey{caller, s.Callee}
			if _, exists := out[k]; !exists {
				out[k] = s
			}
		}
	}
	return out
}

// chainHops decorates a sequence of FQNs with the call-site location
// where each function calls the next. The last hop has empty Path/Line
// because it's the destination, not a bridge.
func chainHops(path []callgraph.FQN, bridges map[bridgeKey]*callgraph.CallSite) []ChainHop {
	if len(path) == 0 {
		return nil
	}
	out := make([]ChainHop, len(path))
	for i, fqn := range path {
		out[i] = ChainHop{Function: fqn}
		if i+1 < len(path) {
			if cs, ok := bridges[bridgeKey{fqn, path[i+1]}]; ok && cs != nil && cs.File != nil {
				out[i].Path = cs.File.Path
				out[i].Line = cs.Line
			}
		}
	}
	return out
}

// shortestPath returns a shortest call chain from src to dst in the
// callee graph, inclusive of both endpoints. Returns nil if dst is
// unreachable; returns [src] when src == dst. Used to render
// interprocedural counterexamples in findings.
func shortestPath(src, dst callgraph.FQN, callees map[callgraph.FQN][]callgraph.FQN) []callgraph.FQN {
	if src == "" || dst == "" {
		return nil
	}
	if src == dst {
		return []callgraph.FQN{src}
	}
	parents := map[callgraph.FQN]callgraph.FQN{src: ""}
	queue := []callgraph.FQN{src}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, c := range callees[n] {
			if _, seen := parents[c]; seen {
				continue
			}
			parents[c] = n
			if c == dst {
				return reconstructPath(parents, src, dst)
			}
			queue = append(queue, c)
		}
	}
	return nil
}

func reconstructPath(parents map[callgraph.FQN]callgraph.FQN, src, dst callgraph.FQN) []callgraph.FQN {
	var rev []callgraph.FQN
	for n := dst; n != ""; n = parents[n] {
		rev = append(rev, n)
		if n == src {
			break
		}
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
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

// firstMatchAny searches calls and fields for the first match. Returns
// (matched, FindingSite, carrier FQN) — `matched` is non-nil if either
// kind found a hit. The carrier is the FQN of the function whose body
// holds the matched site (used to compute counterexample chains).
// Calls are searched first to keep behavior identical when only
// `calls` predicates are used.
func firstMatchAny(m policy.Matcher, sites []*callgraph.CallSite, fields []*callgraph.FieldAccess) (any, FindingSite, callgraph.FQN) {
	for _, s := range sites {
		if matcherMatchesCall(m, s) {
			return s, siteOf(s), s.Caller
		}
	}
	for _, f := range fields {
		if matcherMatchesField(m, f) {
			return f, fieldSiteOf(f), f.Caller
		}
	}
	return nil, FindingSite{}, ""
}

// matcherMatchesCall reports whether the call site matches any `calls`
// predicate in m.
func matcherMatchesCall(m policy.Matcher, site *callgraph.CallSite) bool {
	for _, pred := range m.AnyOf {
		if pred.Kind() == "calls" && callsMatches(pred.Calls, site) {
			return true
		}
	}
	return false
}

// matcherMatchesField reports whether the field access matches any
// `field_access` predicate in m.
func matcherMatchesField(m policy.Matcher, f *callgraph.FieldAccess) bool {
	for _, pred := range m.AnyOf {
		if pred.Kind() == "field_access" && fieldMatches(pred.FieldAccess, f) {
			return true
		}
	}
	return false
}

// fieldSiteOf converts a FieldAccess to a FindingSite. Callee carries
// the full path text so consumers can locate the read.
func fieldSiteOf(f *callgraph.FieldAccess) FindingSite {
	return FindingSite{
		Callee: callgraph.FQN(f.Path),
		Path:   f.File.Path,
		Line:   f.Line,
	}
}

// fieldMatches matches a field-access pattern against a FieldAccess.
// Supported patterns:
//
//	*.<field>     — any access whose attribute is exactly <field>
//	<exact>       — exact path match (e.g. "user.email")
func fieldMatches(pattern string, f *callgraph.FieldAccess) bool {
	if strings.HasPrefix(pattern, "*.") {
		return f.Field == strings.TrimPrefix(pattern, "*.")
	}
	return f.Path == pattern
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
