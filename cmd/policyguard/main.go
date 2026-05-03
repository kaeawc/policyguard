// Command policyguard is a static "the dangerous codepath has the required
// guard" prover. See README.md for the policy DSL.
package main

import (
	"context"
	"os"

	"github.com/kaeawc/policyguard/internal/cli"
)

// version is set at link time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cli.Run(context.Background(), version, os.Args[1:], os.Stdout, os.Stderr))
}
