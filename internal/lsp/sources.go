package lsp

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/kaeawc/policyguard/internal/scanner"
)

// loadSourceTree parses every source file under root that matches the
// language's extensions. Mirrors the equivalent helper in
// internal/cli; kept local so the LSP package doesn't depend on cli.
func loadSourceTree(ctx context.Context, root string, lang scanner.Language) ([]*scanner.File, error) {
	exts := extsFor(lang)
	if len(exts) == 0 {
		return nil, nil
	}
	matchExt := func(p string) bool {
		for _, ext := range exts {
			if strings.HasSuffix(p, ext) {
				return true
			}
		}
		return false
	}
	var out []*scanner.File
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !matchExt(path) {
			return nil
		}
		f, perr := scanner.ParseFile(ctx, path, lang)
		if perr != nil {
			return perr
		}
		out = append(out, f)
		return nil
	})
	return out, err
}

func extsFor(lang scanner.Language) []string {
	switch lang {
	case scanner.LangPython:
		return []string{".py"}
	case scanner.LangTypeScript:
		return []string{".ts", ".tsx"}
	case scanner.LangGo:
		return []string{".go"}
	case scanner.LangJava:
		return []string{".java"}
	default:
		return nil
	}
}
