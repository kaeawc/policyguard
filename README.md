# policyguard — a static "the dangerous codepath has the required guard" prover

## What you're building

Every company shipping AI products has the same shape of internal policy: "if a codepath reaches the model API, it must pass through a redactor first" / "if a function logs a user object, the logger must be the redacting one" / "if a tool writes to disk, it must check the path-confinement helper" / "PII must never reach a third-party SDK." These policies are written in Notion and enforced by code review. Code review is unreliable, and the policies don't compose across services.

policyguard is a Krit-shaped static analyzer where each policy is a rule of the form "any codepath from source X to sink Y must pass through guard G." It proves these contracts statically across a polyglot monorepo.

Architecture mirrors Krit (Go-first, tree-sitter, capability-gated cross-file analysis, single-pass dispatch, multi-frontend). Read `~/kaeawc/krit/CLAUDE.md` and study `internal/scanner/` cross-file indexes — those are the basis for the call-graph this tool needs.

## Policy DSL

A policy is a small YAML file:

```yaml
id: pii-redaction-before-llm
severity: error
languages: [python, typescript, go]
source:
  any_of:
    - calls: "user_repo.get_user"
    - calls: "session.current_user"
    - field_access: "*.email"
sink:
  any_of:
    - calls: "anthropic.messages.create"
    - calls: "openai.chat.completions.create"
guard:
  any_of:
    - calls: "redactor.redact"
    - has_decorator: "@redacted"
message: "User PII reaches LLM call without passing through redactor."
```

The engine builds a call graph, computes reachability from each source to each sink, and asserts every path crosses a guard. A failing path is a finding with the source location, sink location, and the un-guarded path between them.

## Architecture

- **Go**, tree-sitter Python + TypeScript + Go + Java (start with Python and TS).
- **Cross-file call graph** — same machinery as Krit's dead-code detector, generalized.
- **Reachability solver** — bounded interprocedural data-flow.
- **Capability gates** — `NeedsCallGraph` (most rules), `NeedsTypeOracle` (when a sink is a method on a typed object), `NeedsIPC` (cross-service: traces a call into another service's handler if a service map is provided).
- **Outputs**: SARIF, JSON, PR comment with the un-guarded path rendered as a chain of file:line references, LSP, MCP.
- **Autofix tiers** — `idiomatic` (insert the guard call when the fix is unambiguous), never `cosmetic`, semantic only with explicit opt-in.

## MVP

1. Skeleton + tree-sitter Python.
2. Single-language (Python) call graph.
3. Policy YAML loader + reachability solver.
4. Three example policies (PII-before-LLM, log-redaction, path-confinement).
5. CI on a synthetic repo with planted violations + a public Python repo for false-positive baseline.

## Stretch

- **Cross-service mode** — accept an OpenAPI / gRPC spec map; trace a call from service A's handler into service B's endpoint and continue the reachability check.
- **Source-of-truth integration** — pull policies from a central registry (each team owns its policies, shared engine enforces them).
- **Counterexample minimization** — when a policy fails, produce the smallest reproducing snippet.
- **Proof export** — for each enforced policy, emit a machine-readable proof artifact that downstream auditing tools can consume.
- **Java + Kotlin support** — Krit already handles these, lift the parsing layer.

## Why this is the right shape

Policy-as-code exists for infra (OPA, Cedar) but not for application data flow inside polyglot codebases. The bottleneck is having a fast, capability-gated, multi-language call-graph engine — which is exactly what Krit's architecture provides. The DSL keeps policies legible to non-engineers; the engine keeps enforcement fast enough for CI.

## Non-goals

- Runtime enforcement (separate concern, complementary).
- Replacing Semgrep or CodeQL — policyguard is narrower and faster, focused specifically on source→guard→sink contracts.
- Inferring policies; users author them. (A future stretch: mine common patterns and suggest policies.)
