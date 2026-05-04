// Command policyguard-lsp speaks LSP over stdio so editors can
// surface policyguard findings as inline diagnostics. Configuration
// matches the `check` subcommand:
//
//	policyguard-lsp --policies .policies --lang python
//
// Editors invoke this binary as a language server. On didOpen and
// didSave the server re-runs analysis on the workspace and publishes
// diagnostics. didChange is accepted but ignored — saving refreshes
// the report.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kaeawc/policyguard/internal/lsp"
	"github.com/kaeawc/policyguard/internal/scanner"
)

var version = "dev"

func main() {
	policiesDir := flag.String("policies", "", "directory containing policy YAML files")
	lang := flag.String("lang", "python", "source language (python|typescript|go|java)")
	flag.Parse()

	if *policiesDir == "" {
		fmt.Fprintln(os.Stderr, "policyguard-lsp: --policies is required")
		os.Exit(2)
	}

	srv := lsp.NewServer(lsp.Config{
		PoliciesDir: *policiesDir,
		Lang:        scanner.Language(*lang),
		Version:     version,
	}, os.Stdin, os.Stdout, log.New(os.Stderr, "policyguard-lsp: ", 0).Printf)

	if err := srv.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "policyguard-lsp: %v\n", err)
		os.Exit(1)
	}
}
