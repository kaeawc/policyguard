// Package scanner parses source files into tree-sitter ASTs and exposes
// language-agnostic helpers for downstream analyzers (call graph, policy
// engine).
package scanner

import (
	"context"
	"fmt"
	"os"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// Language identifies a supported source language.
type Language string

const (
	LangPython     Language = "python"
	LangTypeScript Language = "typescript"
	LangGo         Language = "go"
	LangJava       Language = "java"
)

// File is a parsed source file plus its tree-sitter tree.
type File struct {
	Path     string
	Language Language
	Source   []byte
	Tree     *sitter.Tree
}

// Root returns the root AST node.
func (f *File) Root() *sitter.Node {
	return f.Tree.RootNode()
}

// ParseFile reads path and parses it as the given language.
func ParseFile(ctx context.Context, path string, lang Language) (*File, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseBytes(ctx, path, lang, src)
}

// ParseBytes parses src as the given language.
func ParseBytes(ctx context.Context, path string, lang Language, src []byte) (*File, error) {
	tsLang, err := tsLanguage(lang)
	if err != nil {
		return nil, err
	}
	parser := sitter.NewParser()
	parser.SetLanguage(tsLang)
	tree, err := parser.ParseCtx(ctx, nil, src)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &File{
		Path:     path,
		Language: lang,
		Source:   src,
		Tree:     tree,
	}, nil
}

func tsLanguage(lang Language) (*sitter.Language, error) {
	switch lang {
	case LangPython:
		return python.GetLanguage(), nil
	case LangTypeScript:
		return typescript.GetLanguage(), nil
	case LangGo:
		return golang.GetLanguage(), nil
	case LangJava:
		return java.GetLanguage(), nil
	default:
		return nil, fmt.Errorf("unsupported language: %s", lang)
	}
}
