package callgraph

import (
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/kaeawc/policyguard/internal/scanner"
)

// BuildPython builds a call graph from a set of parsed Python files.
// rootDir is used to derive module FQNs from file paths; pass "" to use the
// file's basename without extension as the module name.
func BuildPython(files []*scanner.File, rootDir string) *Graph {
	g := NewGraph()
	for _, f := range files {
		if f.Language != scanner.LangPython {
			continue
		}
		modFQN := pythonModuleFQN(f.Path, rootDir)
		ext := newPyExtractor(g, f, modFQN)
		ext.walk(f.Root())
		scanComments(g, f)
	}
	return g
}

func pythonModuleFQN(path, rootDir string) FQN {
	clean := filepath.Clean(path)
	if rootDir != "" {
		if rel, err := filepath.Rel(rootDir, clean); err == nil && !strings.HasPrefix(rel, "..") {
			clean = rel
		}
	}
	clean = strings.TrimSuffix(clean, ".py")
	clean = strings.TrimSuffix(clean, "/__init__")
	parts := strings.Split(clean, string(filepath.Separator))
	return FQN(strings.Join(parts, "."))
}

// pyExtractor walks one file. It tracks the enclosing function/class scope
// stack so it can build FQNs for nested defs and resolve `self`-style calls
// (left as a TODO; methods currently get class-qualified names).
type pyExtractor struct {
	g      *Graph
	file   *scanner.File
	modFQN FQN
	// pkgFQN is the FQN of the package containing this file. For
	// `app/handlers.py` it is `app`; for `app/__init__.py` it is also
	// `app` (the file IS the package). Used to resolve relative
	// imports.
	pkgFQN  FQN
	imports map[string]FQN
	scope   []string // stack of scope segments (class names, function names)
	// curFunc is the FQN of the innermost enclosing function definition,
	// or "" at module scope. This is the Caller field for any call sites
	// observed inside.
	curFunc FQN
}

func newPyExtractor(g *Graph, f *scanner.File, modFQN FQN) *pyExtractor {
	return &pyExtractor{
		g:       g,
		file:    f,
		modFQN:  modFQN,
		pkgFQN:  pythonPackageFQN(f.Path, modFQN),
		imports: make(map[string]FQN),
	}
}

// pythonPackageFQN returns the package FQN containing this file. For
// __init__ files the package is the modFQN itself; for module files it
// is modFQN minus the trailing module name.
func pythonPackageFQN(path string, modFQN FQN) FQN {
	if strings.HasSuffix(path, "/__init__.py") || strings.HasSuffix(path, "__init__.py") && !strings.Contains(path, "/") {
		return modFQN
	}
	parts := strings.Split(string(modFQN), ".")
	if len(parts) <= 1 {
		return ""
	}
	return FQN(strings.Join(parts[:len(parts)-1], "."))
}

// resolveModuleName returns the absolute dotted module name referenced
// by an import_from_statement's `module_name` field. Absolute imports
// (`from app.helpers import ...`) return the dotted_name verbatim.
// Relative imports (`from .helpers import ...` etc.) are anchored to
// the file's package: one dot = current package, two dots = parent,
// and so on. Returns "" when the relative import escapes the project
// root or the package can't be inferred.
func (e *pyExtractor) resolveModuleName(module *sitter.Node) string {
	if module.Type() != "relative_import" {
		return e.text(module)
	}
	var dots int
	var rest string
	for i := 0; i < int(module.NamedChildCount()); i++ {
		c := module.NamedChild(i)
		switch c.Type() {
		case "import_prefix":
			dots = strings.Count(e.text(c), ".")
		case "dotted_name":
			rest = e.text(c)
		}
	}
	base, ok := pythonRelativeBase(e.pkgFQN, dots)
	if !ok {
		// Climbed past the inferred root — can't resolve.
		return ""
	}
	switch {
	case rest == "" && base == "":
		return ""
	case rest == "":
		return string(base)
	case base == "":
		return rest
	default:
		return string(base) + "." + rest
	}
}

// pythonRelativeBase returns the package FQN that a relative import
// with the given dot count anchors against, plus a bool indicating
// whether the climb stayed within the inferred project. One dot =
// current package (pkgFQN unchanged); each additional dot pops a
// segment. Climbing exactly to the root returns "" with ok=true;
// climbing one level past the root returns "" with ok=false.
func pythonRelativeBase(pkgFQN FQN, dots int) (FQN, bool) {
	if dots <= 0 {
		return pkgFQN, true
	}
	pop := dots - 1
	if pkgFQN == "" {
		if pop == 0 {
			return "", true
		}
		return "", false
	}
	parts := strings.Split(string(pkgFQN), ".")
	if pop > len(parts) {
		return "", false
	}
	if pop == 0 {
		return pkgFQN, true
	}
	return FQN(strings.Join(parts[:len(parts)-pop], ".")), true
}

func (e *pyExtractor) walk(n *sitter.Node) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "import_statement":
		e.handleImport(n)
		return
	case "import_from_statement":
		e.handleImportFrom(n)
		return
	case "decorated_definition":
		e.handleDecorated(n)
		return
	case "class_definition":
		e.handleClass(n, nil)
		return
	case "function_definition":
		e.handleFunction(n, nil)
		return
	case "call":
		e.handleCall(n)
		// fall through to recurse into args (which may contain nested calls)
	case "attribute":
		// Record attribute reads (e.g. user.email). Skip when this
		// attribute is the function child of a call expression — those
		// are already captured as call sites.
		if !pyAttrIsCallFunction(n) {
			e.handleFieldAccess(n)
		}
		// Still recurse so nested attributes/calls in `a.b.c` are seen.
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		e.walk(n.NamedChild(i))
	}
}

// pyAttrIsCallFunction reports whether n is the `function` field of an
// enclosing call node — i.e. `obj.method` in `obj.method(...)`. Walks up
// at most one parent.
func pyAttrIsCallFunction(n *sitter.Node) bool {
	parent := n.Parent()
	if parent == nil || parent.Type() != "call" {
		return false
	}
	fn := parent.ChildByFieldName("function")
	return fn != nil && fn == n
}

// handleDecorated walks a decorated_definition: collect decorators, then
// recurse into the inner function or class with those decorators attached.
func (e *pyExtractor) handleDecorated(n *sitter.Node) {
	var decorators []string
	var inner *sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "decorator":
			decorators = append(decorators, decoratorName(c, e.file.Source))
		case "function_definition", "class_definition":
			inner = c
		}
	}
	if inner == nil {
		return
	}
	switch inner.Type() {
	case "function_definition":
		e.handleFunction(inner, decorators)
	case "class_definition":
		e.handleClass(inner, decorators)
	}
}

// decoratorName extracts the decorator's normalized name from its
// expression child. For `@redacted` → "redacted"; `@auth.required` →
// "auth.required"; `@cache(maxsize=10)` → "cache" (the called name).
func decoratorName(dec *sitter.Node, src []byte) string {
	if dec.NamedChildCount() == 0 {
		return ""
	}
	expr := dec.NamedChild(0)
	switch expr.Type() {
	case "call":
		// decorator with arguments — name is the called function expr.
		if fn := expr.ChildByFieldName("function"); fn != nil {
			return fn.Content(src)
		}
	}
	return expr.Content(src)
}

func (e *pyExtractor) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Content(e.file.Source)
}

func (e *pyExtractor) handleImport(n *sitter.Node) {
	// import_statement → name: dotted_name | aliased_import
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "dotted_name":
			full := e.text(c)
			// `import a.b.c` binds local name "a" to module "a.b.c"
			head := strings.SplitN(full, ".", 2)[0]
			e.imports[head] = FQN(full)
		case "aliased_import":
			name := c.ChildByFieldName("name")
			alias := c.ChildByFieldName("alias")
			if name != nil && alias != nil {
				e.imports[e.text(alias)] = FQN(e.text(name))
			}
		}
	}
}

func (e *pyExtractor) handleImportFrom(n *sitter.Node) {
	// from X import Y[, Z as W, ...]
	module := n.ChildByFieldName("module_name")
	if module == nil {
		return
	}
	modName := e.resolveModuleName(module)
	if modName == "" {
		// Relative import that escapes the project root — skip rather
		// than mis-resolve.
		return
	}
	// Iterate children; aliased_import or dotted_name nodes after the module.
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c == module {
			continue
		}
		switch c.Type() {
		case "dotted_name":
			name := e.text(c)
			e.imports[name] = FQN(modName + "." + name)
		case "aliased_import":
			name := c.ChildByFieldName("name")
			alias := c.ChildByFieldName("alias")
			if name != nil && alias != nil {
				e.imports[e.text(alias)] = FQN(modName + "." + e.text(name))
			}
		}
	}
}

func (e *pyExtractor) handleClass(n *sitter.Node, _ []string) {
	name := n.ChildByFieldName("name")
	if name == nil {
		return
	}
	className := e.text(name)
	e.scope = append(e.scope, className)
	defer func() { e.scope = e.scope[:len(e.scope)-1] }()

	body := n.ChildByFieldName("body")
	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			e.walk(body.NamedChild(i))
		}
	}
}

func (e *pyExtractor) handleFunction(n *sitter.Node, decorators []string) {
	name := n.ChildByFieldName("name")
	if name == nil {
		return
	}
	funcName := e.text(name)
	scopePath := append([]string{}, e.scope...)
	scopePath = append(scopePath, funcName)
	fqn := FQN(string(e.modFQN) + "." + strings.Join(scopePath, "."))

	e.g.AddFunc(&FuncNode{
		FQN:        fqn,
		File:       e.file,
		Node:       n,
		Line:       int(n.StartPoint().Row) + 1,
		Decorators: decorators,
	})

	prevFunc := e.curFunc
	e.curFunc = fqn
	e.scope = append(e.scope, funcName)
	defer func() {
		e.curFunc = prevFunc
		e.scope = e.scope[:len(e.scope)-1]
	}()

	body := n.ChildByFieldName("body")
	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			e.walk(body.NamedChild(i))
		}
	}
}

func (e *pyExtractor) handleFieldAccess(n *sitter.Node) {
	// attribute: { object: <expr>, attribute: identifier }
	attr := n.ChildByFieldName("attribute")
	if attr == nil {
		return
	}
	e.g.AddField(&FieldAccess{
		Caller: e.curFunc,
		Field:  e.text(attr),
		Path:   e.text(n),
		File:   e.file,
		Node:   n,
		Line:   int(n.StartPoint().Row) + 1,
	})
}

func (e *pyExtractor) handleCall(n *sitter.Node) {
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

// resolveCallee maps a raw callee expression to an FQN using the import map.
// "redactor.redact" with `from app import redactor` → "app.redactor.redact".
// "anthropic.messages.create" with `import anthropic` → "anthropic.messages.create".
// A bare identifier with no matching import resolves to module-local FQN.
func (e *pyExtractor) resolveCallee(raw string) FQN {
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
	// No import match: assume module-local definition.
	return FQN(string(e.modFQN) + "." + raw)
}
