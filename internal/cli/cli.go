// Package cli wires command-line flags to scanner and (later) policy engine.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/kaeawc/policyguard/internal/scanner"
)

// Run is the main entry point. argv excludes the program name.
func Run(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policyguard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	lang := fs.String("lang", "python", "source language (python)")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "usage: policyguard [--lang LANG] FILE [FILE...]")
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
