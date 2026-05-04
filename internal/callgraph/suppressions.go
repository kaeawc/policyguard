package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/kaeawc/policyguard/internal/scanner"
)

// commentTypes lists every node-type name across the supported tree-
// sitter grammars that represents a comment. Java's grammar
// distinguishes line and block comments; the others use a single
// `comment` type.
var commentTypes = map[string]bool{
	"comment":       true,
	"line_comment":  true,
	"block_comment": true,
}

// scanComments walks the entire AST of f and records any
// `policyguard: ignore <ids>` directives it finds. Used by every
// language extractor as a single, language-agnostic pass: comments
// can live anywhere in a tree (inside function bodies, between class
// members, at module scope) and tree-sitter doesn't always surface
// them through the same body-walk path the rest of the extractor
// uses.
func scanComments(g *Graph, f *scanner.File) {
	root := f.Root()
	if root == nil {
		return
	}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if commentTypes[n.Type()] {
			ids := parseSuppression(n.Content(f.Source))
			if len(ids) > 0 {
				g.AddSuppression(Suppression{
					Path:      f.Path,
					Line:      int(n.StartPoint().Row) + 1,
					PolicyIDs: ids,
				})
			}
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
}

// parseSuppression extracts a `policyguard: ignore <ids>` directive
// from a comment's raw text. The text may include leading `#`, `//`,
// `/*`, surrounding whitespace, and `*/`. Returns the list of policy
// ids the comment suppresses, or nil if the comment isn't a
// suppression directive.
//
// Forms recognized:
//
//	policyguard: ignore foo                  → ["foo"]
//	policyguard: ignore foo, bar             → ["foo", "bar"]
//	policyguard: ignore-all                  → ["*"]
//	policyguard: ignore *                    → ["*"]
func parseSuppression(raw string) []string {
	body := strings.TrimSpace(raw)
	for _, marker := range []string{"//", "/*", "#"} {
		if strings.HasPrefix(body, marker) {
			body = strings.TrimSpace(strings.TrimPrefix(body, marker))
			break
		}
	}
	body = strings.TrimSuffix(body, "*/")
	body = strings.TrimSpace(body)
	const prefix = "policyguard:"
	if !strings.HasPrefix(body, prefix) {
		return nil
	}
	directive := strings.TrimSpace(strings.TrimPrefix(body, prefix))
	switch {
	case directive == "ignore-all", directive == "ignore *":
		return []string{"*"}
	case strings.HasPrefix(directive, "ignore "):
		idsPart := strings.TrimPrefix(directive, "ignore ")
		ids := splitCleanCSV(idsPart)
		if len(ids) == 0 {
			return nil
		}
		return ids
	}
	return nil
}

func splitCleanCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
