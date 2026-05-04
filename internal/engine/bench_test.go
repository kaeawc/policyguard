package engine

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/policy"
	"github.com/kaeawc/policyguard/internal/scanner"
)

// buildSyntheticGraph constructs a graph with n internal functions,
// each calling fanout of its successors plus a few external calls.
// Some functions hit the source predicate, some hit the sink, so a
// non-trivial number of closures end up violating the contract.
func buildSyntheticGraph(n, fanout int) *callgraph.Graph {
	g := callgraph.NewGraph()
	file := &scanner.File{Path: "synthetic.py", Language: scanner.LangPython}
	fn := func(i int) callgraph.FQN {
		return callgraph.FQN("svc.h.f" + strconv.Itoa(i))
	}
	for i := 0; i < n; i++ {
		g.AddFunc(&callgraph.FuncNode{FQN: fn(i), File: file, Line: i + 1})
	}
	// Build call edges: function i calls i+1, i+2, ... up to fanout.
	for i := 0; i < n; i++ {
		caller := fn(i)
		for k := 1; k <= fanout && i+k < n; k++ {
			g.AddCall(&callgraph.CallSite{
				Caller: caller,
				Callee: fn(i + k),
				Raw:    string(fn(i + k)),
				File:   file,
				Line:   (i + 1) * 10,
			})
		}
		// Sprinkle source/sink calls so the engine has work to do.
		switch i % 7 {
		case 0:
			g.AddCall(&callgraph.CallSite{
				Caller: caller,
				Callee: "user_repo.get_user",
				Raw:    "user_repo.get_user",
				File:   file,
				Line:   (i + 1) * 10,
			})
		case 3:
			g.AddCall(&callgraph.CallSite{
				Caller: caller,
				Callee: "anthropic.messages.create",
				Raw:    "anthropic.messages.create",
				File:   file,
				Line:   (i + 1) * 10,
			})
		}
	}
	return g
}

func benchPolicy() *policy.Policy {
	return &policy.Policy{
		ID:        "pii-redaction-before-llm",
		Severity:  policy.SeverityError,
		Languages: []policy.Language{policy.LangPython},
		Source:    policy.Matcher{AnyOf: []policy.Predicate{{Calls: "user_repo.get_user"}}},
		Sink:      policy.Matcher{AnyOf: []policy.Predicate{{Calls: "anthropic.messages.create"}}},
		Guard:     policy.Matcher{AnyOf: []policy.Predicate{{Calls: "redactor.redact"}}},
		Message:   "m",
	}
}

func BenchmarkAnalyze_SmallGraph(b *testing.B) {
	g := buildSyntheticGraph(50, 3)
	p := benchPolicy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Analyze(g, p)
	}
}

func BenchmarkAnalyze_MediumGraph(b *testing.B) {
	g := buildSyntheticGraph(500, 4)
	p := benchPolicy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Analyze(g, p)
	}
}

func BenchmarkAnalyze_LargeGraph(b *testing.B) {
	g := buildSyntheticGraph(2000, 5)
	p := benchPolicy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Analyze(g, p)
	}
}

// BenchmarkAnalyze_PolicySweep measures how throughput scales with the
// number of distinct policies analyzed against the same graph — common
// in real workloads.
func BenchmarkAnalyze_PolicySweep(b *testing.B) {
	g := buildSyntheticGraph(500, 4)
	policies := make([]*policy.Policy, 10)
	for i := range policies {
		p := benchPolicy()
		p.ID = fmt.Sprintf("p-%d", i)
		policies[i] = p
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range policies {
			_ = Analyze(g, p)
		}
	}
}
