package callgraph

import (
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/kaeawc/policyguard/internal/scanner"
)

// BuildTypeScript builds a call graph from a set of parsed TypeScript
// files. rootDir is used to derive module FQNs from file paths.
//
// MVP scope: function_declaration, method_definition, class_declaration,
// import_statement (named, namespace, default), call_expression. Arrow
// functions assigned to lexical bindings are not yet captured — that is
// a follow-up.
func BuildTypeScript(files []*scanner.File, rootDir string) *Graph {
	g := NewGraph()
	for _, f := range files {
		if f.Language != scanner.LangTypeScript {
			continue
		}
		modFQN := tsModuleFQN(f.Path, rootDir)
		ext := newTSExtractor(g, f, modFQN)
		ext.walk(f.Root())
	}
	return g
}

func tsModuleFQN(path, rootDir string) FQN {
	clean := filepath.Clean(path)
	if rootDir != "" {
		if rel, err := filepath.Rel(rootDir, clean); err == nil && !strings.HasPrefix(rel, "..") {
			clean = rel
		}
	}
	for _, ext := range []string{".tsx", ".ts", ".jsx", ".js"} {
		clean = strings.TrimSuffix(clean, ext)
	}
	clean = strings.TrimSuffix(clean, "/index")
	parts := strings.Split(clean, string(filepath.Separator))
	return FQN(strings.Join(parts, "."))
}

type tsExtractor struct {
	g       *Graph
	file    *scanner.File
	modFQN  FQN
	imports map[string]FQN
	scope   []string
	curFunc FQN
}

func newTSExtractor(g *Graph, f *scanner.File, modFQN FQN) *tsExtractor {
	return &tsExtractor{
		g:       g,
		file:    f,
		modFQN:  modFQN,
		imports: make(map[string]FQN),
	}
}

func (e *tsExtractor) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Content(e.file.Source)
}

func (e *tsExtractor) walk(n *sitter.Node) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "import_statement":
		e.handleImport(n)
		return
	case "function_declaration":
		e.handleFunction(n)
		return
	case "class_declaration":
		e.handleClass(n)
		return
	case "method_definition":
		e.handleMethod(n)
		return
	case "lexical_declaration", "variable_declaration":
		e.handleVariableDeclaration(n)
		return
	case "export_statement":
		e.handleExport(n)
		return
	case "call_expression":
		e.handleCall(n)
		// fall through to recurse into args
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		e.walk(n.NamedChild(i))
	}
}

// handleImport parses `import ... from '<source>';` and populates the
// import map. Three forms supported:
//
//   - import { a, b as c } from 'pkg'    — bind a and c to pkg.a / pkg.b
//   - import * as ns from 'pkg'          — bind ns to pkg
//   - import def from 'pkg'              — bind def to pkg.default
func (e *tsExtractor) handleImport(n *sitter.Node) {
	source := tsImportSource(n, e.file.Source)
	if source == "" {
		return
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() != "import_clause" {
			continue
		}
		e.handleImportClause(c, source)
	}
}

func tsImportSource(n *sitter.Node, src []byte) string {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() != "string" {
			continue
		}
		// string -> string_fragment ("path"). Take the fragment text.
		for j := 0; j < int(c.NamedChildCount()); j++ {
			if frag := c.NamedChild(j); frag.Type() == "string_fragment" {
				return frag.Content(src)
			}
		}
	}
	return ""
}

func (e *tsExtractor) handleImportClause(clause *sitter.Node, source string) {
	for i := 0; i < int(clause.NamedChildCount()); i++ {
		c := clause.NamedChild(i)
		switch c.Type() {
		case "identifier":
			// default import: `import def from 'pkg'`
			e.imports[e.text(c)] = FQN(source + ".default")
		case "namespace_import":
			// `* as ns`
			for j := 0; j < int(c.NamedChildCount()); j++ {
				if id := c.NamedChild(j); id.Type() == "identifier" {
					e.imports[e.text(id)] = FQN(source)
				}
			}
		case "named_imports":
			for j := 0; j < int(c.NamedChildCount()); j++ {
				spec := c.NamedChild(j)
				if spec.Type() != "import_specifier" {
					continue
				}
				e.handleImportSpecifier(spec, source)
			}
		}
	}
}

func (e *tsExtractor) handleImportSpecifier(spec *sitter.Node, source string) {
	name := spec.ChildByFieldName("name")
	alias := spec.ChildByFieldName("alias")
	if name == nil {
		// Fall back: first identifier child.
		for i := 0; i < int(spec.NamedChildCount()); i++ {
			if id := spec.NamedChild(i); id.Type() == "identifier" {
				name = id
				break
			}
		}
	}
	if name == nil {
		return
	}
	original := e.text(name)
	local := original
	if alias != nil {
		local = e.text(alias)
	}
	e.imports[local] = FQN(source + "." + original)
}

// handleVariableDeclaration captures arrow-function and function-
// expression bindings:
//
//	const foo = () => { ... };
//	let bar = function() { ... };
//
// The binding name becomes the function FQN. Bindings whose initializer
// isn't a function are walked normally (their initializers may contain
// nested calls or class expressions).
func (e *tsExtractor) handleVariableDeclaration(n *sitter.Node) {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		decl := n.NamedChild(i)
		if decl.Type() != "variable_declarator" {
			e.walk(decl)
			continue
		}
		e.handleVariableDeclarator(decl)
	}
}

func (e *tsExtractor) handleVariableDeclarator(decl *sitter.Node) {
	name := decl.ChildByFieldName("name")
	value := decl.ChildByFieldName("value")
	if name == nil || value == nil {
		// Walk children to surface any nested calls/declarations.
		for i := 0; i < int(decl.NamedChildCount()); i++ {
			e.walk(decl.NamedChild(i))
		}
		return
	}
	switch value.Type() {
	case "arrow_function", "function_expression":
		if name.Type() != "identifier" {
			// Destructuring bindings (object/array patterns) — not yet
			// supported; just walk the initializer for nested calls.
			e.walk(value)
			return
		}
		e.recordAndRecurse(value, e.text(name))
	default:
		e.walk(value)
	}
}

// handleExport unwraps `export ...` so the inner declaration (function,
// class, lexical binding) is processed normally.
func (e *tsExtractor) handleExport(n *sitter.Node) {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		e.walk(n.NamedChild(i))
	}
}

func (e *tsExtractor) handleClass(n *sitter.Node) {
	// class_declaration: type_identifier (name), class_body (members)
	var name *sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == "type_identifier" {
			name = c
			break
		}
	}
	if name == nil {
		return
	}
	className := e.text(name)
	e.scope = append(e.scope, className)
	defer func() { e.scope = e.scope[:len(e.scope)-1] }()
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == "class_body" {
			for j := 0; j < int(c.NamedChildCount()); j++ {
				e.walk(c.NamedChild(j))
			}
		}
	}
}

func (e *tsExtractor) handleMethod(n *sitter.Node) {
	// method_definition: property_identifier (name), formal_parameters, body
	var name *sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == "property_identifier" {
			name = c
			break
		}
	}
	if name == nil {
		return
	}
	e.recordAndRecurse(n, e.text(name))
}

func (e *tsExtractor) handleFunction(n *sitter.Node) {
	name := n.ChildByFieldName("name")
	if name == nil {
		// Fall back: first identifier child.
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
	e.recordAndRecurse(n, e.text(name))
}

func (e *tsExtractor) recordAndRecurse(defNode *sitter.Node, funcName string) {
	scopePath := append([]string{}, e.scope...)
	scopePath = append(scopePath, funcName)
	fqn := FQN(string(e.modFQN) + "." + strings.Join(scopePath, "."))
	e.g.AddFunc(&FuncNode{
		FQN:  fqn,
		File: e.file,
		Node: defNode,
		Line: int(defNode.StartPoint().Row) + 1,
	})

	prevFunc := e.curFunc
	e.curFunc = fqn
	e.scope = append(e.scope, funcName)
	defer func() {
		e.curFunc = prevFunc
		e.scope = e.scope[:len(e.scope)-1]
	}()

	body := defNode.ChildByFieldName("body")
	if body == nil {
		// Fall back: first statement_block child.
		for i := 0; i < int(defNode.NamedChildCount()); i++ {
			if c := defNode.NamedChild(i); c.Type() == "statement_block" {
				body = c
				break
			}
		}
	}
	if body == nil {
		return
	}
	if body.Type() == "statement_block" {
		// Block body: recurse into each statement.
		for i := 0; i < int(body.NamedChildCount()); i++ {
			e.walk(body.NamedChild(i))
		}
		return
	}
	// Expression body (concise arrow): walk the expression itself.
	e.walk(body)
}

func (e *tsExtractor) handleCall(n *sitter.Node) {
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

// resolveCallee maps a raw callee expression to an FQN using the import
// map. Mirror of the Python resolver: if the head segment is imported,
// rewrite it; otherwise treat as module-local.
func (e *tsExtractor) resolveCallee(raw string) FQN {
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
	return FQN(string(e.modFQN) + "." + raw)
}
