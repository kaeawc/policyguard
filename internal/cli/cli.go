// Package cli wires command-line flags to scanner, callgraph, and (later)
// policy engine.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/scanner"
)

// Run is the main entry point. argv excludes the program name. version is
// the build-time version string injected via -ldflags.
func Run(ctx context.Context, version string, argv []string, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := argv[0], argv[1:]
	switch cmd {
	case "parse":
		return runParse(ctx, rest, stdout, stderr)
	case "callgraph":
		return runCallgraph(ctx, rest, stdout, stderr)
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, version)
		return 0
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "policyguard: unknown command %q\n", cmd)
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: policyguard <command> [args]")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  parse     [--lang LANG] FILE [FILE...]   Parse files and print AST root info.")
	fmt.Fprintln(w, "  callgraph [--lang LANG] DIR              Build a call graph for a directory.")
	fmt.Fprintln(w, "  version                                  Print the policyguard version.")
}

func runParse(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	fs.SetOutput(stderr)
	lang := fs.String("lang", "python", "source language (python)")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "usage: policyguard parse [--lang LANG] FILE [FILE...]")
		return 2
	}
	for _, path := range paths {
		file, err := scanner.ParseFile(ctx, path, scanner.Language(*lang))
		if err != nil {
			fmt.Fprintf(stderr, "policyguard: %v\n", err)
			return 1
		}
		root := file.Root()
		fmt.Fprintf(stdout, "%s: lang=%s root=%s children=%d\n",
			file.Path, file.Language, root.Type(), root.ChildCount())
	}
	return 0
}

func runCallgraph(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("callgraph", flag.ContinueOnError)
	fset.SetOutput(stderr)
	lang := fset.String("lang", "python", "source language (python)")
	if err := fset.Parse(argv); err != nil {
		return 2
	}
	dirs := fset.Args()
	if len(dirs) != 1 {
		fmt.Fprintln(stderr, "usage: policyguard callgraph [--lang LANG] DIR")
		return 2
	}
	root := dirs[0]
	files, err := loadDir(ctx, root, scanner.Language(*lang))
	if err != nil {
		fmt.Fprintf(stderr, "policyguard: %v\n", err)
		return 1
	}
	if len(files) == 0 {
		fmt.Fprintf(stderr, "policyguard: no %s files under %s\n", *lang, root)
		return 1
	}

	var g *callgraph.Graph
	switch scanner.Language(*lang) {
	case scanner.LangPython:
		g = callgraph.BuildPython(files, root)
	default:
		fmt.Fprintf(stderr, "policyguard: callgraph not implemented for %s\n", *lang)
		return 1
	}
	dumpGraph(stdout, g)
	return 0
}

func loadDir(ctx context.Context, root string, lang scanner.Language) ([]*scanner.File, error) {
	ext := extForLang(lang)
	if ext == "" {
		return nil, fmt.Errorf("unknown language: %s", lang)
	}
	var out []*scanner.File
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ext) {
			return nil
		}
		file, perr := scanner.ParseFile(ctx, path, lang)
		if perr != nil {
			return perr
		}
		out = append(out, file)
		return nil
	})
	return out, err
}

func extForLang(lang scanner.Language) string {
	switch lang {
	case scanner.LangPython:
		return ".py"
	default:
		return ""
	}
}

func dumpGraph(w io.Writer, g *callgraph.Graph) {
	fns := make([]string, 0, len(g.Funcs))
	for fqn := range g.Funcs {
		fns = append(fns, string(fqn))
	}
	sort.Strings(fns)

	fmt.Fprintf(w, "functions: %d\n", len(fns))
	for _, fqn := range fns {
		fn := g.Funcs[callgraph.FQN(fqn)]
		fmt.Fprintf(w, "  %s  (%s:%d)\n", fqn, fn.File.Path, fn.Line)
	}

	callers := make([]string, 0, len(g.Calls))
	for c := range g.Calls {
		callers = append(callers, string(c))
	}
	sort.Strings(callers)

	totalCalls := 0
	for _, sites := range g.Calls {
		totalCalls += len(sites)
	}
	fmt.Fprintf(w, "calls: %d\n", totalCalls)
	for _, c := range callers {
		caller := callgraph.FQN(c)
		label := c
		if label == "" {
			label = "<module>"
		}
		for _, site := range g.Calls[caller] {
			fmt.Fprintf(w, "  %s -> %s  (%s:%d", label, site.Callee, site.File.Path, site.Line)
			if string(site.Callee) != site.Raw {
				fmt.Fprintf(w, "  raw=%s", site.Raw)
			}
			fmt.Fprintln(w, ")")
		}
	}
}
