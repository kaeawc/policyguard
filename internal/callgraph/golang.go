package callgraph

import (
	"bufio"
	"os"
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
// rootDir is used to derive package FQNs from file paths. When rootDir
// (or any ancestor) contains a go.mod, the module path declared there
// is used as the FQN prefix and the directory parts use slash
// separators — so a file at <root>/cmd/server/main.go in module
// `github.com/me/proj` produces FQN prefix
// `github.com/me/proj/cmd/server`. Without a go.mod, the legacy dot-
// separated form (`cmd.server`) is used, which is enough for
// fixtures and self-contained tests.
func BuildGo(files []*scanner.File, rootDir string) *Graph {
	g := NewGraph()
	modulePath := findGoModulePath(rootDir)
	for _, f := range files {
		if f.Language != scanner.LangGo {
			continue
		}
		modFQN := goModuleFQN(f.Path, rootDir, modulePath)
		ext := newGoExtractor(g, f, modFQN)
		ext.walk(f.Root())
		scanComments(g, f)
	}
	return g
}

// goModuleFQN derives a module FQN from the file's directory. When a
// modulePath is provided (read from go.mod), the FQN uses slash
// separators (`<modulePath>/<rel-dir>`); otherwise it falls back to
// the dot-separated form (`<rel-dir-with-dots>`).
func goModuleFQN(path, rootDir, modulePath string) FQN {
	clean := filepath.Clean(path)
	if rootDir != "" {
		if rel, err := filepath.Rel(rootDir, clean); err == nil && !strings.HasPrefix(rel, "..") {
			clean = rel
		}
	}
	dir := filepath.Dir(clean)
	if dir == "." {
		dir = ""
	}
	if modulePath != "" {
		dirSlash := filepath.ToSlash(dir)
		if dirSlash == "" {
			return FQN(modulePath)
		}
		return FQN(modulePath + "/" + dirSlash)
	}
	if dir == "" {
		return ""
	}
	parts := strings.Split(dir, string(filepath.Separator))
	return FQN(strings.Join(parts, "."))
}

// findGoModulePath walks up from rootDir looking for a go.mod and
// returns its declared module path. Empty string means no go.mod was
// found or the file couldn't be parsed — callers fall back to the
// directory-based FQN form.
func findGoModulePath(rootDir string) string {
	if rootDir == "" {
		return ""
	}
	abs, err := filepath.Abs(rootDir)
	if err != nil {
		return ""
	}
	dir := abs
	for {
		modPath := parseGoModFile(filepath.Join(dir, "go.mod"))
		if modPath != "" {
			return modPath
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// parseGoModFile reads a go.mod at the given path and returns the
// `module ...` declaration's path. Returns "" on any error or when no
// module line is present.
func parseGoModFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanr := bufio.NewScanner(f)
	for scanr.Scan() {
		line := strings.TrimSpace(scanr.Text())
		if !strings.HasPrefix(line, "module ") && line != "module" {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		rest = strings.Trim(rest, "\"")
		if rest != "" {
			return rest
		}
	}
	return ""
}

type goExtractor struct {
	g       *Graph
	file    *scanner.File
	modFQN  FQN
	imports map[string]FQN
	curFunc FQN
	// localTypes maps a parameter / receiver name to its declared type
	// FQN (canonical: an `<import-path>.TypeName` for imported types,
	// or `<modFQN>.TypeName` for same-package types). Reset per function.
	// Untyped variables (`x := f()`) are not tracked — type inference
	// is a follow-up.
	localTypes map[string]string
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
	params := firstChildOfType(n, "parameter_list")
	e.recordAndRecurse(n, e.text(name), "", params, nil)
}

func (e *goExtractor) handleMethod(n *sitter.Node) {
	// method_declaration: parameter_list (receiver) + field_identifier (name) + parameter_list (args) + body
	var recv, params *sitter.Node
	var name string
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "parameter_list":
			if recv == nil {
				recv = c
			} else if params == nil {
				params = c
			}
		case "field_identifier":
			name = e.text(c)
		}
	}
	if name == "" {
		return
	}
	recvType := goReceiverType(recv, e.file.Source)
	e.recordAndRecurse(n, name, recvType, params, recv)
}

// goReceiverType extracts the type name from a method receiver list.
// `(f *Foo)` → "Foo"; `(Foo)` → "Foo".
func goReceiverType(paramList *sitter.Node, src []byte) string {
	if paramList == nil {
		return ""
	}
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

func (e *goExtractor) recordAndRecurse(defNode *sitter.Node, funcName, receiverType string, params, recv *sitter.Node) {
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
	prevLocals := e.localTypes
	e.curFunc = fqn
	e.localTypes = e.seedLocalTypes(params, recv)
	defer func() {
		e.curFunc = prevFunc
		e.localTypes = prevLocals
	}()

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

// seedLocalTypes builds the function's parameter type map. Each entry
// maps a parameter name to its type FQN (with imports resolved when
// applicable). The receiver list is treated like a parameter list.
func (e *goExtractor) seedLocalTypes(params, recv *sitter.Node) map[string]string {
	out := make(map[string]string)
	for _, list := range []*sitter.Node{recv, params} {
		if list == nil {
			continue
		}
		for i := 0; i < int(list.NamedChildCount()); i++ {
			c := list.NamedChild(i)
			if c.Type() != "parameter_declaration" {
				continue
			}
			typeFQN := e.goParamTypeFQN(c)
			if typeFQN == "" {
				continue
			}
			for j := 0; j < int(c.NamedChildCount()); j++ {
				if id := c.NamedChild(j); id.Type() == "identifier" {
					out[e.text(id)] = typeFQN
				}
			}
		}
	}
	return out
}

// goParamTypeFQN extracts the FQN of a parameter_declaration's type.
// Handles type_identifier (same-package), qualified_type
// (imported pkg.Type), pointer_type wrapping either, and a few common
// composite forms (slice, array). Returns "" when the type can't be
// resolved.
func (e *goExtractor) goParamTypeFQN(decl *sitter.Node) string {
	for i := 0; i < int(decl.NamedChildCount()); i++ {
		c := decl.NamedChild(i)
		switch c.Type() {
		case "identifier":
			// Parameter name — skip.
			continue
		}
		if fqn := e.goTypeFQN(c); fqn != "" {
			return fqn
		}
	}
	return ""
}

func (e *goExtractor) goTypeFQN(n *sitter.Node) string {
	switch n.Type() {
	case "type_identifier":
		return e.localTypeFQN(e.text(n))
	case "qualified_type":
		return e.qualifiedTypeFQN(n)
	case "pointer_type", "slice_type", "array_type", "channel_type", "parenthesized_type":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if fqn := e.goTypeFQN(n.NamedChild(i)); fqn != "" {
				return fqn
			}
		}
	}
	return ""
}

func (e *goExtractor) localTypeFQN(name string) string {
	if e.modFQN != "" {
		return string(e.modFQN) + "." + name
	}
	return name
}

func (e *goExtractor) qualifiedTypeFQN(n *sitter.Node) string {
	var pkg, ty string
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		switch c.Type() {
		case "package_identifier":
			pkg = e.text(c)
		case "type_identifier":
			ty = e.text(c)
		}
	}
	if pkg == "" || ty == "" {
		return ""
	}
	if mapped, ok := e.imports[pkg]; ok {
		return string(mapped) + "." + ty
	}
	return pkg + "." + ty
}

// firstChildOfType returns the first named child whose type matches t,
// or nil.
func firstChildOfType(n *sitter.Node, t string) *sitter.Node {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == t {
			return c
		}
	}
	return nil
}

func (e *goExtractor) handleCall(n *sitter.Node) {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return
	}
	raw := e.text(fn)
	resolved := e.resolveCallee(raw)
	// Receiver-aware resolution: when fn is `selector_expression` whose
	// operand is a single identifier of a tracked type, prefer
	// `<typeFQN>.<field>` over the raw-text fallback.
	if fn.Type() == "selector_expression" {
		operand := fn.ChildByFieldName("operand")
		field := fn.ChildByFieldName("field")
		if operand != nil && field != nil && operand.Type() == "identifier" {
			if typeFQN, ok := e.localTypes[e.text(operand)]; ok {
				resolved = FQN(typeFQN + "." + e.text(field))
			}
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
