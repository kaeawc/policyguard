package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/kaeawc/policyguard/internal/scanner"
)

// BuildJava builds a call graph from a set of parsed Java files.
//
// Module FQN comes from the file's `package` declaration, not the file
// path — Java has explicit package statements, so we don't need to
// guess from directory structure.
//
// Imports are resolved by last segment: `import com.foo.Bar` binds the
// local name "Bar" to "com.foo.Bar". `import com.foo.*` (on-demand) and
// static imports are not yet handled.
//
// Method invocations of the form `obj.method(args)` produce CallSites
// whose Raw text is `obj.method` (the variable-qualified name); the
// engine's raw-text fallback lets policies match these without
// receiver-type tracking. Bare invocations `method(args)` resolve to
// `<modFQN>.<ClassName>.method` when inside a class — see method
// scope below.
//
// Limitations (documented for follow-up):
//   - Variable-of-class-type tracking. `Redactor r = ...; r.redact(...)`
//     only matches via `r.redact` raw text; the policy must use that
//     name rather than the class's FQN.
//   - On-demand and static imports.
//   - Generics, lambdas, and method references — bodies are walked but
//     these constructs aren't specially recognized.
func BuildJava(files []*scanner.File, rootDir string) *Graph {
	_ = rootDir // package_declaration is authoritative for FQNs
	g := NewGraph()
	for _, f := range files {
		if f.Language != scanner.LangJava {
			continue
		}
		ext := newJavaExtractor(g, f)
		ext.walk(f.Root())
		scanComments(g, f)
	}
	return g
}

type javaExtractor struct {
	g       *Graph
	file    *scanner.File
	pkg     FQN // module FQN derived from `package ...;`
	imports map[string]FQN
	scope   []string // class nesting
	curFunc FQN
	// classFields maps a field's simple name to its declared type
	// (e.g. "redactor" -> "Redactor"). Populated in a pre-pass when
	// entering a class.
	classFields map[string]string
	// localTypes maps a local variable / parameter name to its
	// declared type. Reset on entering each method, seeded from
	// classFields plus the method's formal parameters.
	localTypes map[string]string
}

func newJavaExtractor(g *Graph, f *scanner.File) *javaExtractor {
	return &javaExtractor{
		g:       g,
		file:    f,
		imports: make(map[string]FQN),
	}
}

func (e *javaExtractor) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Content(e.file.Source)
}

func (e *javaExtractor) walk(n *sitter.Node) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "package_declaration":
		e.handlePackage(n)
		return
	case "import_declaration":
		e.handleImport(n)
		return
	case "class_declaration", "interface_declaration", "record_declaration":
		e.handleClass(n)
		return
	case "method_declaration", "constructor_declaration":
		e.handleMethod(n)
		return
	case "local_variable_declaration":
		e.recordLocalDeclaration(n)
		// fall through to recurse into the initializer (which may
		// contain calls)
	case "method_invocation":
		e.handleInvocation(n)
		// fall through to recurse into args
	case "field_access":
		if !javaFieldAccessIsCallReceiver(n) {
			e.handleFieldAccess(n)
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		e.walk(n.NamedChild(i))
	}
}

func (e *javaExtractor) handlePackage(n *sitter.Node) {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == "identifier" || c.Type() == "scoped_identifier" {
			e.pkg = FQN(e.text(c))
			return
		}
	}
}

func (e *javaExtractor) handleImport(n *sitter.Node) {
	// import_declaration may have `static` modifier and trailing `.*`,
	// represented as separate children. We pick the rightmost
	// identifier path and key on its last segment.
	var path string
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == "scoped_identifier" || c.Type() == "identifier" {
			path = e.text(c)
		}
	}
	if path == "" {
		return
	}
	last := path
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		last = path[idx+1:]
	}
	if last == "*" {
		// On-demand import — skip for the MVP.
		return
	}
	e.imports[last] = FQN(path)
}

func (e *javaExtractor) handleClass(n *sitter.Node) {
	var name string
	var body *sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "identifier":
			if name == "" {
				name = e.text(c)
			}
		case "class_body", "interface_body", "record_body":
			body = c
		}
	}
	if name == "" {
		return
	}
	e.scope = append(e.scope, name)
	prevFields := e.classFields
	e.classFields = e.collectFieldTypes(body)
	defer func() {
		e.scope = e.scope[:len(e.scope)-1]
		e.classFields = prevFields
	}()
	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			e.walk(body.NamedChild(i))
		}
	}
}

// collectFieldTypes walks a class body and returns the map of field
// simple-name -> declared type name. Only field_declaration nodes are
// considered; nested classes are out of scope.
func (e *javaExtractor) collectFieldTypes(body *sitter.Node) map[string]string {
	out := make(map[string]string)
	if body == nil {
		return out
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		c := body.NamedChild(i)
		if c.Type() != "field_declaration" {
			continue
		}
		typeName := e.javaTypeName(c)
		if typeName == "" {
			continue
		}
		for j := 0; j < int(c.NamedChildCount()); j++ {
			vc := c.NamedChild(j)
			if vc.Type() != "variable_declarator" {
				continue
			}
			for k := 0; k < int(vc.NamedChildCount()); k++ {
				if id := vc.NamedChild(k); id.Type() == "identifier" {
					out[e.text(id)] = typeName
					break
				}
			}
		}
	}
	return out
}

// javaTypeName extracts the declared simple type name from a node that
// has a leading type_identifier or scoped_type_identifier, optionally
// inside a generic_type wrapper. Returns "" on `var` (inferred type)
// since we don't infer.
func (e *javaExtractor) javaTypeName(n *sitter.Node) string {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "type_identifier":
			t := e.text(c)
			if t == "var" {
				return ""
			}
			return t
		case "scoped_type_identifier":
			full := e.text(c)
			if idx := strings.LastIndex(full, "."); idx >= 0 {
				return full[idx+1:]
			}
			return full
		case "generic_type":
			// generic_type wraps a type_identifier or scoped_type_identifier.
			return e.javaTypeName(c)
		}
	}
	return ""
}

func (e *javaExtractor) handleMethod(n *sitter.Node) {
	var name string
	var body *sitter.Node
	var params *sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "identifier":
			if name == "" {
				name = e.text(c)
			}
		case "formal_parameters":
			params = c
		case "block", "constructor_body":
			body = c
		}
	}
	if name == "" {
		return
	}
	parts := []string{}
	if e.pkg != "" {
		parts = append(parts, string(e.pkg))
	}
	parts = append(parts, e.scope...)
	parts = append(parts, name)
	fqn := FQN(strings.Join(parts, "."))

	e.g.AddFunc(&FuncNode{
		FQN:  fqn,
		File: e.file,
		Node: n,
		Line: int(n.StartPoint().Row) + 1,
	})

	prevFunc := e.curFunc
	prevLocals := e.localTypes
	e.curFunc = fqn
	e.localTypes = e.seedLocalTypes(params)
	defer func() {
		e.curFunc = prevFunc
		e.localTypes = prevLocals
	}()

	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			e.walk(body.NamedChild(i))
		}
	}
}

// seedLocalTypes returns the starting locals map for a method: class
// fields plus formal parameters. New locals from local_variable_
// declaration nodes are added during body walk.
func (e *javaExtractor) seedLocalTypes(params *sitter.Node) map[string]string {
	out := make(map[string]string, len(e.classFields))
	for k, v := range e.classFields {
		out[k] = v
	}
	if params == nil {
		return out
	}
	for i := 0; i < int(params.NamedChildCount()); i++ {
		c := params.NamedChild(i)
		if c.Type() != "formal_parameter" {
			continue
		}
		typeName := e.javaTypeName(c)
		if typeName == "" {
			continue
		}
		for j := 0; j < int(c.NamedChildCount()); j++ {
			if id := c.NamedChild(j); id.Type() == "identifier" {
				out[e.text(id)] = typeName
				break
			}
		}
	}
	return out
}

// recordLocalDeclaration captures `Type name = ...` and
// `Type name1, name2;` style local declarations. Called during walk.
func (e *javaExtractor) recordLocalDeclaration(n *sitter.Node) {
	if e.localTypes == nil {
		return
	}
	typeName := e.javaTypeName(n)
	if typeName == "" {
		return
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		vc := n.NamedChild(i)
		if vc.Type() != "variable_declarator" {
			continue
		}
		for j := 0; j < int(vc.NamedChildCount()); j++ {
			if id := vc.NamedChild(j); id.Type() == "identifier" {
				e.localTypes[e.text(id)] = typeName
				break
			}
		}
	}
}

func (e *javaExtractor) handleInvocation(n *sitter.Node) {
	// method_invocation children:
	//   bare:  identifier (name) + argument_list
	//   member: identifier-or-field_access (object) + identifier (name) + argument_list
	var object, name *sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "argument_list":
			// skip
		case "type_arguments":
			// skip
		default:
			if name == nil {
				// First non-argument child — could be bare name or object.
				name = c
			} else {
				// We already saw one identifier-ish child; the second
				// is the method name and the first was the object.
				object = name
				name = c
			}
		}
	}
	if name == nil {
		return
	}
	var raw string
	if object != nil {
		raw = e.text(object) + "." + e.text(name)
	} else {
		raw = e.text(name)
	}
	callee := e.resolveCallee(raw, object == nil)
	// If the receiver is a single identifier whose type we know, prefer
	// the type-resolved FQN over the raw-text fallback. We still leave
	// Raw set to the original expression so policies that match by raw
	// (e.g. `redactor.redact`) keep working.
	if object != nil && object.Type() == "identifier" {
		if typeFQN, ok := e.lookupReceiverFQN(e.text(object)); ok {
			callee = FQN(typeFQN + "." + e.text(name))
		}
	}
	e.g.AddCall(&CallSite{
		Caller: e.curFunc,
		Callee: callee,
		Raw:    raw,
		File:   e.file,
		Node:   n,
		Line:   int(n.StartPoint().Row) + 1,
	})
}

// lookupReceiverFQN returns the canonical type FQN for a variable name
// using the current method's local-type map and the import map. Returns
// false if the variable name isn't tracked or its type can't be
// resolved. Same-package types fall back to <pkg>.<TypeName>.
func (e *javaExtractor) lookupReceiverFQN(varName string) (string, bool) {
	if e.localTypes == nil {
		return "", false
	}
	typeName, ok := e.localTypes[varName]
	if !ok {
		return "", false
	}
	if path, ok := e.imports[typeName]; ok {
		return string(path), true
	}
	if e.pkg != "" {
		return string(e.pkg) + "." + typeName, true
	}
	return typeName, true
}

// resolveCallee maps a raw invocation expression to an FQN. If the head
// segment matches an imported simple name, the import path is
// substituted. Bare invocations (no receiver) inside a class resolve to
// `<pkg>.<EnclosingClass>.<method>` so module-local helpers register
// against their declared FQN.
func (e *javaExtractor) resolveCallee(raw string, bare bool) FQN {
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
	if bare {
		// Bare invocation: same-class helper.
		segs := []string{}
		if e.pkg != "" {
			segs = append(segs, string(e.pkg))
		}
		segs = append(segs, e.scope...)
		segs = append(segs, raw)
		return FQN(strings.Join(segs, "."))
	}
	if e.pkg == "" {
		return FQN(raw)
	}
	return FQN(string(e.pkg) + "." + raw)
}

func javaFieldAccessIsCallReceiver(n *sitter.Node) bool {
	parent := n.Parent()
	if parent == nil || parent.Type() != "method_invocation" {
		return false
	}
	// In tree-sitter-java the invocation's object is the first named
	// child. If `n` is that first child, treat it as the receiver.
	if parent.NamedChildCount() > 0 && parent.NamedChild(0) == n {
		return true
	}
	return false
}

func (e *javaExtractor) handleFieldAccess(n *sitter.Node) {
	// field_access: object + field (identifier)
	var field *sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == "identifier" {
			field = c
		}
	}
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
