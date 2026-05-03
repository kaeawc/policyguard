# policyguard

Static "the dangerous codepath has the required guard" prover. Reads polyglot
source with tree-sitter, builds a cross-file call graph, and proves
source → guard → sink contracts authored as YAML policies.

Architecture mirrors [krit](https://github.com/kaeawc/krit). When in doubt
about call-graph internals, capability gating, or cross-file index design,
study `~/kaeawc/krit/internal/scanner/`.

## Key rules

- Go-first. Tree-sitter for parsing; never raw regex for structural checks.
- After implementation changes run `go build -o policyguard ./cmd/policyguard/ && go vet ./...`.
- Run `go test ./... -count=1` for full validation; focused package tests while iterating.
- Add positive and negative fixtures under `tests/fixtures/<lang>/`.
- Each policy must have a positive (violation) and negative (compliant) fixture.

## Project structure

- `cmd/policyguard/` — CLI entry point.
- `internal/cli/` — flag parsing, top-level dispatch.
- `internal/scanner/` — tree-sitter parsing, file model, cross-file indexes (later).
- `internal/policy/` — YAML policy loader, schema (later).
- `internal/callgraph/` — interprocedural call graph + reachability solver (later).
- `tests/fixtures/<lang>/` — positive and negative fixtures per policy.

## Build & validate

```bash
go build -o policyguard ./cmd/policyguard/
go vet ./...
go test ./... -count=1
```

## MVP roadmap

1. Skeleton + tree-sitter Python  ← done.
2. Single-language Python call graph.
3. Policy YAML loader + reachability solver.
4. Three example policies (PII-before-LLM, log-redaction, path-confinement).
5. CI on a synthetic repo with planted violations + a public Python repo for
   false-positive baseline.
