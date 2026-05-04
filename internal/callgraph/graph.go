// Package callgraph builds an interprocedural call graph from parsed source
// files. The graph is the input to the reachability solver that proves
// source → guard → sink contracts.
//
// Design (MVP):
//   - Internal nodes are functions/methods defined in the project, keyed by
//     a fully-qualified name (FQN) like "pkg.module.func" or
//     "pkg.module.Class.method".
//   - External nodes are referenced names we cannot resolve to a definition
//     (third-party calls, builtins). They appear in the graph as terminals
//     so the policy engine can pattern-match against their FQN.
//   - Edges go from a caller FuncNode to one or more callees. A single call
//     site may resolve to several callees if name resolution is ambiguous.
package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/kaeawc/policyguard/internal/scanner"
)

// FQN is a fully-qualified name. Dots separate scopes.
// Examples: "app.handlers.fetch", "app.models.User.save", "anthropic.messages.create".
type FQN string

// Graph holds all functions, call edges, attribute reads, and
// suppression annotations discovered across a set of files.
type Graph struct {
	// Funcs is keyed by FQN. Includes only project-defined functions.
	Funcs map[FQN]*FuncNode
	// Calls collects every call site, indexed by caller FQN. The slice
	// preserves source order. A call site whose caller is the empty FQN
	// originates at module scope.
	Calls map[FQN][]*CallSite
	// Fields collects every attribute/member-expression read site,
	// indexed by caller FQN. Attribute accesses that are themselves the
	// callee of a call site are NOT included here (they're already
	// represented in Calls), so a single `obj.method()` shows up once.
	Fields map[FQN][]*FieldAccess
	// Suppressions records `policyguard: ignore <ids>` annotations
	// extracted from source comments. Indexed by file path; each entry
	// holds the line number plus the matched policy IDs (or `*` for
	// catch-all).
	Suppressions map[string][]Suppression
}

// NewGraph returns an empty graph.
func NewGraph() *Graph {
	return &Graph{
		Funcs:        make(map[FQN]*FuncNode),
		Calls:        make(map[FQN][]*CallSite),
		Fields:       make(map[FQN][]*FieldAccess),
		Suppressions: make(map[string][]Suppression),
	}
}

// Suppression is one `policyguard: ignore <ids>` annotation from source.
// PolicyIDs is the list of ids the comment matches; the special id
// "*" indicates a catch-all suppression.
type Suppression struct {
	Path      string
	Line      int
	PolicyIDs []string
}

// AddSuppression appends a suppression for the given file.
func (g *Graph) AddSuppression(s Suppression) {
	g.Suppressions[s.Path] = append(g.Suppressions[s.Path], s)
}

// MatchSuppression reports whether some suppression on the given file
// covers the given line for the given policy id. A suppression on line
// L applies to lines L (inline) and L+1 (the line after the comment),
// so both `func() # policyguard: ignore X` and the more common
//
//	# policyguard: ignore X
//	func()
//
// form work.
func (g *Graph) MatchSuppression(path string, line int, policyID string) bool {
	for _, s := range g.Suppressions[path] {
		if s.Line != line && s.Line+1 != line {
			continue
		}
		for _, id := range s.PolicyIDs {
			if id == "*" || id == policyID {
				return true
			}
		}
	}
	return false
}

// FuncNode is a function or method defined in the project.
type FuncNode struct {
	FQN  FQN
	File *scanner.File
	// Node is the function's definition node in the tree-sitter AST.
	Node *sitter.Node
	// Line is the 1-based line of the definition.
	Line int
	// Decorators are the decorator expressions attached to the function
	// (without the leading `@`). For `@auth.required` this is
	// `auth.required`; for `@cache(maxsize=10)` it is `cache` — the
	// expression text up to the call's function.
	Decorators []string
}

// CallSite is a single call expression observed in a function body (or at
// module scope).
type CallSite struct {
	// Caller is the FQN of the enclosing function, or "" for module scope.
	Caller FQN
	// Callee is the textual callee name, possibly resolved via imports.
	// Examples: "anthropic.messages.create", "app.redactor.redact".
	Callee FQN
	// Raw is the unresolved callee text as it appears in source. Useful
	// when import resolution fails so the policy engine can still see
	// the original.
	Raw  string
	File *scanner.File
	Node *sitter.Node
	Line int
}

// FieldAccess records a single attribute read like `user.email`.
type FieldAccess struct {
	// Caller is the FQN of the enclosing function, or "" for module scope.
	Caller FQN
	// Field is just the attribute name (`email` for `user.email`).
	Field string
	// Path is the full expression text as it appears in source
	// (`user.email`, `request.user.email`, etc.). Useful for exact-path
	// matchers.
	Path string
	File *scanner.File
	Node *sitter.Node
	Line int
}

// AddFunc registers a function definition. Duplicate FQNs overwrite — Python
// allows redefinition, and we keep the latest.
func (g *Graph) AddFunc(fn *FuncNode) {
	g.Funcs[fn.FQN] = fn
}

// AddCall appends a call site under its caller key.
func (g *Graph) AddCall(c *CallSite) {
	g.Calls[c.Caller] = append(g.Calls[c.Caller], c)
}

// AddField appends a field-access site under its caller key.
func (g *Graph) AddField(f *FieldAccess) {
	g.Fields[f.Caller] = append(g.Fields[f.Caller], f)
}
