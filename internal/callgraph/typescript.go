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
		scanComments(g, f)
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
	// classFields maps a field's simple name to its declared type
	// (e.g. "redactor" -> "Redactor"). Populated on entry to a class.
	classFields map[string]string
	// classFQN is the FQN of the enclosing class — used to resolve
	// `this.method()` calls. Empty outside class methods.
	classFQN FQN
	// localTypes maps a parameter / variable name to its declared type
	// FQN. Reset per function. `this` is included when inside a class
	// method.
	localTypes map[string]string
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
	case "member_expression":
		// Attribute read like `user.email`. Skip when this is the
		// function child of a call_expression — those are call sites.
		if !tsMemberIsCallFunction(n) {
			e.handleFieldAccess(n)
		}
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
	var body *sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "type_identifier":
			if name == nil {
				name = c
			}
		case "class_body":
			body = c
		}
	}
	if name == nil {
		return
	}
	className := e.text(name)
	e.scope = append(e.scope, className)
	prevFields := e.classFields
	prevClassFQN := e.classFQN
	e.classFields = e.collectTSFieldTypes(body)
	e.classFQN = FQN(string(e.modFQN) + "." + className)
	defer func() {
		e.scope = e.scope[:len(e.scope)-1]
		e.classFields = prevFields
		e.classFQN = prevClassFQN
	}()
	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			e.walk(body.NamedChild(i))
		}
	}
}

// collectTSFieldTypes walks a class_body and returns the map of field
// simple-name -> declared type name, drawn from public_field_definition
// nodes that carry a type_annotation.
func (e *tsExtractor) collectTSFieldTypes(body *sitter.Node) map[string]string {
	out := make(map[string]string)
	if body == nil {
		return out
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		c := body.NamedChild(i)
		if c.Type() != "public_field_definition" {
			continue
		}
		var name string
		var typeName string
		for j := 0; j < int(c.NamedChildCount()); j++ {
			cc := c.NamedChild(j)
			switch cc.Type() {
			case "property_identifier":
				name = e.text(cc)
			case "type_annotation":
				typeName = e.tsTypeName(cc)
			}
		}
		if name != "" && typeName != "" {
			out[name] = typeName
		}
	}
	return out
}

// tsTypeName extracts the simple type name from a type_annotation. The
// annotation's first named child is the actual type node. Generic
// wrappers (`Foo<T>`) collapse to `Foo`. Returns "" for predefined
// types (`string`, `number`) since those don't map to imports.
func (e *tsExtractor) tsTypeName(annotation *sitter.Node) string {
	if annotation == nil {
		return ""
	}
	for i := 0; i < int(annotation.NamedChildCount()); i++ {
		c := annotation.NamedChild(i)
		switch c.Type() {
		case "type_identifier":
			return e.text(c)
		case "generic_type":
			// First named child of generic_type is the type_identifier.
			for j := 0; j < int(c.NamedChildCount()); j++ {
				if id := c.NamedChild(j); id.Type() == "type_identifier" {
					return e.text(id)
				}
			}
		}
	}
	return ""
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
	prevLocals := e.localTypes
	e.curFunc = fqn
	e.scope = append(e.scope, funcName)
	e.localTypes = e.seedTSLocalTypes(defNode)
	defer func() {
		e.curFunc = prevFunc
		e.localTypes = prevLocals
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

func tsMemberIsCallFunction(n *sitter.Node) bool {
	parent := n.Parent()
	if parent == nil || parent.Type() != "call_expression" {
		return false
	}
	fn := parent.ChildByFieldName("function")
	return fn != nil && fn == n
}

func (e *tsExtractor) handleFieldAccess(n *sitter.Node) {
	// member_expression: object + property (property_identifier).
	prop := n.ChildByFieldName("property")
	if prop == nil {
		return
	}
	e.g.AddField(&FieldAccess{
		Caller: e.curFunc,
		Field:  e.text(prop),
		Path:   e.text(n),
		File:   e.file,
		Node:   n,
		Line:   int(n.StartPoint().Row) + 1,
	})
}

// seedTSLocalTypes builds the function/method's locals map: typed
// formal parameters (looked up via tsTypeName), plus `this` when
// inside a class method.
func (e *tsExtractor) seedTSLocalTypes(defNode *sitter.Node) map[string]string {
	out := make(map[string]string)
	if e.classFQN != "" {
		out["this"] = string(e.classFQN)
	}
	params := firstTSChildOfType(defNode, "formal_parameters")
	if params == nil {
		return out
	}
	for i := 0; i < int(params.NamedChildCount()); i++ {
		p := params.NamedChild(i)
		if p.Type() != "required_parameter" && p.Type() != "optional_parameter" {
			continue
		}
		if name, typeFQN := e.tsParamNameAndTypeFQN(p); name != "" && typeFQN != "" {
			out[name] = typeFQN
		}
	}
	return out
}

func (e *tsExtractor) tsParamNameAndTypeFQN(p *sitter.Node) (string, string) {
	var name, typeName string
	for j := 0; j < int(p.NamedChildCount()); j++ {
		c := p.NamedChild(j)
		switch c.Type() {
		case "identifier":
			if name == "" {
				name = e.text(c)
			}
		case "type_annotation":
			typeName = e.tsTypeName(c)
		}
	}
	if name == "" || typeName == "" {
		return "", ""
	}
	return name, e.tsTypeFQN(typeName)
}

func firstTSChildOfType(n *sitter.Node, t string) *sitter.Node {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == t {
			return c
		}
	}
	return nil
}

func (e *tsExtractor) handleCall(n *sitter.Node) {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return
	}
	raw := e.text(fn)
	resolved := e.resolveCallee(raw)
	if fn.Type() == "member_expression" {
		if typed, ok := e.tsResolveMember(fn); ok {
			resolved = typed
		}
	}
	e.g.AddCall(&CallSite{
		Caller: e.curFunc,
		Callee: resolved,
		Raw:    raw,
		File:   e.file,
		Node:   n,
		Line:   int(n.StartPoint().Row) + 1,
	})
}

// tsResolveMember resolves `<obj>.<prop>` to its canonical FQN when
// `<obj>` is a tracked variable. Supports:
//   - identifier:        `r.method()`        → typeFQN(r) + "." + method
//   - this:              `this.method()`     → classFQN + "." + method
//   - this.<field>:      `this.f.method()`   → classFields[f] type FQN + "." + method
func (e *tsExtractor) tsResolveMember(member *sitter.Node) (FQN, bool) {
	object := member.ChildByFieldName("object")
	property := member.ChildByFieldName("property")
	if object == nil || property == nil {
		return "", false
	}
	method := e.text(property)
	switch object.Type() {
	case "identifier":
		if t, ok := e.localTypes[e.text(object)]; ok {
			return FQN(t + "." + method), true
		}
	case "this":
		if e.classFQN != "" {
			return FQN(string(e.classFQN) + "." + method), true
		}
	case "member_expression":
		// Handle `this.<field>.method`: object is a member_expression
		// whose object is `this` and property is a known class field.
		innerObj := object.ChildByFieldName("object")
		innerProp := object.ChildByFieldName("property")
		if innerObj != nil && innerProp != nil && innerObj.Type() == "this" {
			fieldName := e.text(innerProp)
			if typeName, ok := e.classFields[fieldName]; ok {
				typeFQN := e.tsTypeFQN(typeName)
				return FQN(typeFQN + "." + method), true
			}
		}
	}
	return "", false
}

// tsTypeFQN turns a simple type name into its FQN by consulting the
// import map; falls back to module-local for unmapped names.
func (e *tsExtractor) tsTypeFQN(typeName string) string {
	if mapped, ok := e.imports[typeName]; ok {
		return string(mapped)
	}
	return string(e.modFQN) + "." + typeName
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
