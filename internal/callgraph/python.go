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
		ext.walk(f.Root(), nil)
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
	g       *Graph
	file    *scanner.File
	modFQN  FQN
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
		imports: make(map[string]FQN),
	}
}

func (e *pyExtractor) walk(n *sitter.Node, parent *sitter.Node) {
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
	case "class_definition":
		e.handleClass(n)
		return
	case "function_definition":
		e.handleFunction(n)
		return
	case "call":
		e.handleCall(n)
		// fall through to recurse into args (which may contain nested calls)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		e.walk(n.NamedChild(i), n)
	}
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
	modName := e.text(module)
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

func (e *pyExtractor) handleClass(n *sitter.Node) {
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
			e.walk(body.NamedChild(i), body)
		}
	}
}

func (e *pyExtractor) handleFunction(n *sitter.Node) {
	name := n.ChildByFieldName("name")
	if name == nil {
		return
	}
	funcName := e.text(name)
	scopePath := append([]string{}, e.scope...)
	scopePath = append(scopePath, funcName)
	fqn := FQN(string(e.modFQN) + "." + strings.Join(scopePath, "."))

	e.g.AddFunc(&FuncNode{
		FQN:  fqn,
		File: e.file,
		Node: n,
		Line: int(n.StartPoint().Row) + 1,
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
			e.walk(body.NamedChild(i), body)
		}
	}
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
