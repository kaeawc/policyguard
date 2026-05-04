package callgraph

import (
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/kaeawc/policyguard/internal/scanner"
)

// BuildGo builds a call graph from a set of parsed Go files.
//
// MVP scope:
//   - function_declaration and method_declaration are registered as
//     FuncNodes. Methods get a receiver-type-qualified FQN
//     (`<pkg>.<RecvType>.<Method>`); pointer receivers (`*Foo`) collapse
//     to `Foo`.
//   - Imports support the bare `"path"` form (head = last path segment)
//     and the aliased `name "path"` form. Dot-imports and blank imports
//     are ignored.
//   - call_expression callees are resolved via the import map; selector
//     expressions whose head isn't imported fall back to the local
//     package FQN, so module-internal calls like `loadUser(id)` register
//     as `<pkg>.loadUser`.
//   - Limitation: a callsite like `obj.Method()` resolves to
//     `<pkg>.obj.Method` (the variable name path) rather than
//     `<pkg>.<RecvType>.Method` — receiver-type tracking is a follow-up.
//   - Limitation: import paths are taken verbatim, so internal-package
//     callsites only match an internal function FQN when the policy or
//     fixture uses an import path that aligns with the module FQN
//     derived from rootDir.
//
// rootDir is used to derive package FQNs from file paths: an .go file
// at <rootDir>/cmd/server/main.go produces FQN prefix "cmd.server".
func BuildGo(files []*scanner.File, rootDir string) *Graph {
	g := NewGraph()
	for _, f := range files {
		if f.Language != scanner.LangGo {
			continue
		}
		modFQN := goModuleFQN(f.Path, rootDir)
		ext := newGoExtractor(g, f, modFQN)
		ext.walk(f.Root())
	}
	return g
}

// goModuleFQN derives a module FQN from the file's directory.
// `cmd/server/main.go` (under root) → `cmd.server`. A top-level file
// (e.g. root/main.go) yields the empty FQN, which the extractor
// special-cases below.
func goModuleFQN(path, rootDir string) FQN {
	clean := filepath.Clean(path)
	if rootDir != "" {
		if rel, err := filepath.Rel(rootDir, clean); err == nil && !strings.HasPrefix(rel, "..") {
			clean = rel
		}
	}
	dir := filepath.Dir(clean)
	if dir == "." {
		return ""
	}
	parts := strings.Split(dir, string(filepath.Separator))
	return FQN(strings.Join(parts, "."))
}

type goExtractor struct {
	g       *Graph
	file    *scanner.File
	modFQN  FQN
	imports map[string]FQN
	curFunc FQN
}

func newGoExtractor(g *Graph, f *scanner.File, modFQN FQN) *goExtractor {
	return &goExtractor{
		g:       g,
		file:    f,
		modFQN:  modFQN,
		imports: make(map[string]FQN),
	}
}

func (e *goExtractor) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Content(e.file.Source)
}

func (e *goExtractor) walk(n *sitter.Node) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "import_declaration":
		e.handleImportDeclaration(n)
		return
	case "function_declaration":
		e.handleFunction(n)
		return
	case "method_declaration":
		e.handleMethod(n)
		return
	case "call_expression":
		e.handleCall(n)
		// fall through to recurse into args
	case "selector_expression":
		// Bare attribute read like `user.Email`. Skip when this is the
		// function child of a call_expression — those are call sites.
		if !goSelectorIsCallFunction(n) {
			e.handleFieldAccess(n)
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		e.walk(n.NamedChild(i))
	}
}

func (e *goExtractor) handleImportDeclaration(n *sitter.Node) {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "import_spec":
			e.handleImportSpec(c)
		case "import_spec_list":
			for j := 0; j < int(c.NamedChildCount()); j++ {
				if cc := c.NamedChild(j); cc.Type() == "import_spec" {
					e.handleImportSpec(cc)
				}
			}
		}
	}
}

func (e *goExtractor) handleImportSpec(spec *sitter.Node) {
	var alias string
	var path string
	for i := 0; i < int(spec.NamedChildCount()); i++ {
		c := spec.NamedChild(i)
		switch c.Type() {
		case "package_identifier":
			alias = e.text(c)
		case "blank_identifier", "dot":
			// `_ "path"` and `. "path"` skipped.
			alias = c.Type()
		case "interpreted_string_literal", "raw_string_literal":
			path = strings.Trim(e.text(c), "`\"")
		}
	}
	if path == "" || alias == "blank_identifier" || alias == "dot" {
		return
	}
	if alias == "" {
		alias = goLastSegment(path)
	}
	e.imports[alias] = FQN(path)
}

func goLastSegment(path string) string {
	// Strip trailing /v2-style version suffix and return the last
	// non-version segment as the package's local name.
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		seg := parts[i]
		if seg == "" {
			continue
		}
		if isGoVersionSegment(seg) {
			continue
		}
		return seg
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}

func isGoVersionSegment(seg string) bool {
	if len(seg) < 2 || seg[0] != 'v' {
		return false
	}
	for _, r := range seg[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (e *goExtractor) handleFunction(n *sitter.Node) {
	name := n.ChildByFieldName("name")
	if name == nil {
		// Fall back to first identifier child.
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if c := n.NamedChild(i); c.Type() == "identifier" {
				name = c
				break
			}
		}
	}
	if name == nil {
		return
	}
	e.recordAndRecurse(n, e.text(name), "")
}

func (e *goExtractor) handleMethod(n *sitter.Node) {
	// method_declaration: parameter_list (receiver) + field_identifier (name) + parameter_list (args) + body
	var recvType string
	var name string
	seenParam := false
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "parameter_list":
			if !seenParam {
				recvType = goReceiverType(c, e.file.Source)
				seenParam = true
			}
		case "field_identifier":
			name = e.text(c)
		}
	}
	if name == "" {
		return
	}
	e.recordAndRecurse(n, name, recvType)
}

// goReceiverType extracts the type name from a method receiver list.
// `(f *Foo)` → "Foo"; `(Foo)` → "Foo".
func goReceiverType(paramList *sitter.Node, src []byte) string {
	for i := 0; i < int(paramList.NamedChildCount()); i++ {
		decl := paramList.NamedChild(i)
		if decl.Type() != "parameter_declaration" {
			continue
		}
		for j := 0; j < int(decl.NamedChildCount()); j++ {
			c := decl.NamedChild(j)
			switch c.Type() {
			case "type_identifier":
				return c.Content(src)
			case "pointer_type":
				for k := 0; k < int(c.NamedChildCount()); k++ {
					if t := c.NamedChild(k); t.Type() == "type_identifier" {
						return t.Content(src)
					}
				}
			}
		}
	}
	return ""
}

func (e *goExtractor) recordAndRecurse(defNode *sitter.Node, funcName, receiverType string) {
	parts := []string{}
	if e.modFQN != "" {
		parts = append(parts, string(e.modFQN))
	}
	if receiverType != "" {
		parts = append(parts, receiverType)
	}
	parts = append(parts, funcName)
	fqn := FQN(strings.Join(parts, "."))

	e.g.AddFunc(&FuncNode{
		FQN:  fqn,
		File: e.file,
		Node: defNode,
		Line: int(defNode.StartPoint().Row) + 1,
	})

	prevFunc := e.curFunc
	e.curFunc = fqn
	defer func() { e.curFunc = prevFunc }()

	body := defNode.ChildByFieldName("body")
	if body == nil {
		for i := 0; i < int(defNode.NamedChildCount()); i++ {
			if c := defNode.NamedChild(i); c.Type() == "block" {
				body = c
				break
			}
		}
	}
	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			e.walk(body.NamedChild(i))
		}
	}
}

func (e *goExtractor) handleCall(n *sitter.Node) {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return
	}
	raw := e.text(fn)
	resolved := e.resolveCallee(raw)
	e.g.AddCall(&CallSite{
		Caller: e.curFunc,
		Callee: resolved,
		Raw:    raw,
		File:   e.file,
		Node:   n,
		Line:   int(n.StartPoint().Row) + 1,
	})
}

func (e *goExtractor) resolveCallee(raw string) FQN {
	parts := strings.Split(raw, ".")
	if len(parts) == 0 {
		return FQN(raw)
	}
	head := parts[0]
	if mapped, ok := e.imports[head]; ok {
		if len(parts) == 1 {
			return mapped
		}
		return FQN(string(mapped) + "." + strings.Join(parts[1:], "."))
	}
	if e.modFQN == "" {
		return FQN(raw)
	}
	return FQN(string(e.modFQN) + "." + raw)
}

func goSelectorIsCallFunction(n *sitter.Node) bool {
	parent := n.Parent()
	if parent == nil || parent.Type() != "call_expression" {
		return false
	}
	fn := parent.ChildByFieldName("function")
	return fn != nil && fn == n
}

func (e *goExtractor) handleFieldAccess(n *sitter.Node) {
	field := n.ChildByFieldName("field")
	if field == nil {
		return
	}
	e.g.AddField(&FieldAccess{
		Caller: e.curFunc,
		Field:  e.text(field),
		Path:   e.text(n),
		File:   e.file,
		Node:   n,
		Line:   int(n.StartPoint().Row) + 1,
	})
}
