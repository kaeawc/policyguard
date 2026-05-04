package servicemap

import (
	"strings"
	"testing"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/scanner"
)

func TestParse_Valid(t *testing.T) {
	body := `edges:
  - from: redactor_client.send
    to: redactor_service.handle
  - from: api_client.post.*
    to: user_service.create
`
	m, err := Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Edges) != 2 {
		t.Fatalf("Edges = %d", len(m.Edges))
	}
	if m.Edges[0].From != "redactor_client.send" || m.Edges[0].To != "redactor_service.handle" {
		t.Errorf("Edges[0] = %+v", m.Edges[0])
	}
}

func TestParse_RejectsMissingFields(t *testing.T) {
	cases := []string{
		`edges:
  - from: ""
    to: x.y
`,
		`edges:
  - from: x.y
    to: ""
`,
	}
	for _, body := range cases {
		_, err := Parse(strings.NewReader(body))
		if err == nil {
			t.Errorf("expected error for body:\n%s", body)
		}
	}
}

func TestParse_EmptyFile(t *testing.T) {
	m, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Edges) != 0 {
		t.Errorf("empty file should produce empty map; got %+v", m)
	}
}

func TestApply_AddsSyntheticEdge(t *testing.T) {
	g := callgraph.NewGraph()
	file := &scanner.File{Path: "a.py", Language: scanner.LangPython}
	const (
		caller callgraph.FQN = "service_a.handler"
		server callgraph.FQN = "service_b.handle_redact"
	)
	g.AddFunc(&callgraph.FuncNode{FQN: caller, File: file, Line: 1})
	g.AddFunc(&callgraph.FuncNode{FQN: server, File: file, Line: 1})
	g.AddCall(&callgraph.CallSite{
		Caller: caller,
		Callee: "client.send_redact",
		Raw:    "client.send_redact",
		File:   file,
		Line:   5,
	})

	Apply(g, &Map{Edges: []Edge{{From: "client.send_redact", To: string(server)}}})

	calls := g.Calls[caller]
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls (original + synthetic); got %+v", calls)
	}
	var synthetic *callgraph.CallSite
	for _, c := range calls {
		if c.Callee == server {
			synthetic = c
		}
	}
	if synthetic == nil {
		t.Fatalf("missing synthetic edge to %q", server)
	}
	if synthetic.Line != 5 {
		t.Errorf("synthetic line = %d, want 5 (preserves client-call location)", synthetic.Line)
	}
}

func TestApply_SkipsEdgeToUnknownTarget(t *testing.T) {
	g := callgraph.NewGraph()
	file := &scanner.File{Path: "a.py", Language: scanner.LangPython}
	const caller callgraph.FQN = "service_a.handler"
	g.AddFunc(&callgraph.FuncNode{FQN: caller, File: file, Line: 1})
	g.AddCall(&callgraph.CallSite{
		Caller: caller,
		Callee: "client.send_redact",
		Raw:    "client.send_redact",
		File:   file,
		Line:   5,
	})
	Apply(g, &Map{Edges: []Edge{{From: "client.send_redact", To: "missing.handler"}}})
	if len(g.Calls[caller]) != 1 {
		t.Errorf("expected no synthetic edge when target is unknown; calls = %+v", g.Calls[caller])
	}
}

func TestApply_WildcardFrom(t *testing.T) {
	g := callgraph.NewGraph()
	file := &scanner.File{Path: "a.py", Language: scanner.LangPython}
	const (
		caller callgraph.FQN = "a.h"
		server callgraph.FQN = "b.handle"
	)
	g.AddFunc(&callgraph.FuncNode{FQN: caller, File: file, Line: 1})
	g.AddFunc(&callgraph.FuncNode{FQN: server, File: file, Line: 1})
	for _, raw := range []string{"api_client.post.users", "api_client.post.orders"} {
		g.AddCall(&callgraph.CallSite{
			Caller: caller,
			Callee: callgraph.FQN(raw),
			Raw:    raw,
			File:   file,
			Line:   5,
		})
	}
	Apply(g, &Map{Edges: []Edge{{From: "api_client.post.*", To: string(server)}}})
	count := 0
	for _, c := range g.Calls[caller] {
		if c.Callee == server {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 synthetic edges (one per matching call); got %d", count)
	}
}
