// Package servicemap loads and applies cross-service edges to a call
// graph. A service map is a YAML file declaring `from -> to` pairs:
// when the call graph contains a call site matching `from`, the engine
// treats it as also calling `to`. Use this to wire HTTP/gRPC client
// calls to the server-side handler so reachability continues across
// service boundaries.
//
// Schema:
//
//	edges:
//	  - from: redactor_client.send_redact
//	    to: redactor_service.handle_redact
//	  - from: api_client.post_user.*
//	    to: user_service.create_user
//
// `from` supports the same forms as the policy `calls` predicate:
// exact callee FQN or trailing `.*` wildcard. `to` must resolve to a
// function defined in the analyzed graph; bridges to undefined targets
// are silently dropped.
package servicemap

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kaeawc/policyguard/internal/callgraph"
)

// Map is a parsed service map.
type Map struct {
	Edges []Edge `yaml:"edges"`
}

// Edge declares one synthetic call-graph edge. When a CallSite's
// resolved Callee or raw text matches From, the engine adds a
// synthetic CallSite from the same caller to To.
type Edge struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// Load parses and validates a service map from path.
func Load(path string) (*Map, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	m, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// Parse reads YAML from r and validates the resulting map.
func Parse(r io.Reader) (*Map, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var m Map
	if err := dec.Decode(&m); err != nil {
		if errors.Is(err, io.EOF) {
			return &Map{}, nil
		}
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate returns the first structural error in m.
func (m *Map) Validate() error {
	for i, e := range m.Edges {
		if e.From == "" {
			return fmt.Errorf("edges[%d].from: required", i)
		}
		if e.To == "" {
			return fmt.Errorf("edges[%d].to: required", i)
		}
	}
	return nil
}

// Apply mutates g by adding a synthetic call edge for every CallSite
// matching an edge's From clause. The synthetic site keeps the caller
// FQN, file, and line of the original site so counterexample chains
// surface the cross-service hop at the client call's source location.
//
// Edges whose To doesn't resolve to a known internal function in g
// are skipped silently — analyzing only one side of the system is a
// valid use case (the missing service's handler simply doesn't get
// traversed).
func Apply(g *callgraph.Graph, m *Map) {
	if g == nil || m == nil {
		return
	}
	for _, edge := range m.Edges {
		if _, ok := g.Funcs[callgraph.FQN(edge.To)]; !ok {
			continue
		}
		applyEdge(g, edge)
	}
}

func applyEdge(g *callgraph.Graph, edge Edge) {
	type pendingCall struct {
		caller callgraph.FQN
		site   *callgraph.CallSite
	}
	var pending []pendingCall
	for caller, sites := range g.Calls {
		for _, site := range sites {
			if !edgeMatches(edge.From, site) {
				continue
			}
			pending = append(pending, pendingCall{caller: caller, site: site})
		}
	}
	for _, p := range pending {
		g.AddCall(&callgraph.CallSite{
			Caller: p.caller,
			Callee: callgraph.FQN(edge.To),
			Raw:    edge.To,
			File:   p.site.File,
			Node:   p.site.Node,
			Line:   p.site.Line,
		})
	}
}

func edgeMatches(pattern string, site *callgraph.CallSite) bool {
	callee := string(site.Callee)
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		if callee == prefix || strings.HasPrefix(callee, prefix+".") {
			return true
		}
		if site.Raw == prefix || strings.HasPrefix(site.Raw, prefix+".") {
			return true
		}
		return false
	}
	return callee == pattern || site.Raw == pattern
}
