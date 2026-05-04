# policyguard

Static "the dangerous codepath has the required guard" prover. Reads
polyglot source with tree-sitter, builds a closure-based interprocedural
call graph, and proves source → guard → sink contracts authored as YAML
policies.

Architecture mirrors [krit](https://github.com/kaeawc/krit). When in
doubt about call-graph internals or cross-file index design, study
`~/kaeawc/krit/internal/scanner/`.

## Key rules

- Go-first. Tree-sitter for parsing; never raw regex for structural checks.
- After implementation changes run `go build -o policyguard ./cmd/policyguard/ && go vet ./...`.
- `make check-fixtures` exercises the binary end-to-end against every
  bundled compliant/violating fixture.
- Run `go test ./... -count=1` for full validation; focused package
  tests while iterating.
- Add positive (compliant) and negative (violating) fixtures under
  `tests/fixtures/<lang>/policies/<policy-id>/`. Variants like
  `compliant_decorated/` or `violating_interprocedural/` drop in
  automatically — the fixture script matches `compliant*` / `violating*`
  prefixes.

## Project structure

- `cmd/policyguard/` — CLI entry point (`parse`, `callgraph`, `check`,
  `version`).
- `internal/cli/` — flag parsing, top-level dispatch.
- `internal/scanner/` — tree-sitter parsers for Python, TypeScript, Go,
  Java.
- `internal/callgraph/` — per-language extractors. Each language has
  its own file (`python.go`, `typescript.go`, `golang.go`, `java.go`).
  Java/Go/TS extractors track receiver types from parameters and class
  fields so `obj.method()` resolves to the canonical
  `<type-FQN>.method`.
- `internal/policy/` — YAML policy loader + validation. Policies
  declare `source`, `sink`, `guard` (each a `Matcher` with `any_of`
  predicates) plus optional `fix` block.
- `internal/engine/` — closure-based reachability solver. Produces
  findings with source/sink endpoints, minimal-violator dedup, and
  counterexample chains (file:line per hop).
- `internal/output/` — text, JSON, SARIF, and markdown renderers.
- `tests/integration/` — end-to-end tests that drive each example
  policy through the full pipeline against its fixtures.
- `tests/fixtures/<lang>/policies/` — fixtures organized by language
  then by policy id.
- `examples/policies/` — canonical example policies.
- `action.yml` — composite GitHub Action wrapping the binary.

## Build & validate

```bash
go build -o policyguard ./cmd/policyguard/
go vet ./...
go test ./... -count=1
make check-fixtures           # binary against bundled fixtures
golangci-lint run             # style + complexity gate
```

## Adding a language

1. Add the tree-sitter grammar binding to `internal/scanner/parser.go`
   and a new `Language` constant.
2. Create `internal/callgraph/<lang>.go` with `Build<Lang>(files,
   rootDir)`. Mirror the pattern from `golang.go` / `typescript.go`:
   extract package/module FQN, imports, function/method definitions,
   call expressions, field reads. Track receiver types from
   parameters and class fields if the language has them.
3. Wire into `internal/cli/cli.go` — `extForLang`, the `runCheck` /
   `runCallgraph` switch.
4. Wire into `tests/integration/examples_test.go`'s `runPipeline`.
5. Add a fixture tree under `tests/fixtures/<lang>/policies/<id>/`
   with `compliant/` and `violating/` subtrees.
6. Add an integration subtest invoking `runExample`.

## Adding a predicate kind

1. Add the field to `policy.Predicate` and update `Predicate.Kind` /
   `Predicate.Value`.
2. Update validation in `policy.go` (the predicate-shape check).
3. If the predicate matches a new kind of evidence (not call sites),
   add an extraction stage to each language extractor and a
   corresponding map on `callgraph.Graph`.
4. Update `engine.firstMatchAny` (or the decorator/field helpers) to
   apply the new predicate.
5. Add unit tests + a fixture demonstrating the new predicate.

## Architecture invariants

- **Closure-based interprocedural analysis.** For each internal
  function F, the closure is F plus every function transitively
  reachable. Violations fire on closures, not single functions.
  Module-scope code stays intra-procedural.
- **Minimal-violator dedup.** When F calls G and both closures
  violate, only G is reported — unless G's closure equals F's (cycle),
  in which case both are kept.
- **Counterexample chains.** Each finding carries SourceChain and
  SinkChain — shortest BFS paths from violator → source-containing
  function and violator → sink-containing function. Each non-terminal
  hop carries the bridging call site's path/line so renderers can
  link to it.
- **Raw-text fallback.** Every CallSite preserves the original
  callee expression text so policies authored against variable-name
  paths still match even when receiver-type tracking resolves the
  Callee to a canonical FQN.
- **Determinism.** Findings sort by function FQN then source line.
  Tests that depend on order should match this.
