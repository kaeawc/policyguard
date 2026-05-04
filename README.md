# policyguard — a static "the dangerous codepath has the required guard" prover

Every company shipping AI products has the same shape of internal policy: "if a codepath reaches the model API, it must pass through a redactor first" / "if a function logs a user object, the logger must be the redacting one" / "if a tool writes to disk, it must check the path-confinement helper" / "PII must never reach a third-party SDK." These policies are written in Notion and enforced by code review. Code review is unreliable, and the policies don't compose across services.

policyguard is a static analyzer where each policy is a rule of the form **"any codepath from source X to sink Y must pass through guard G."** It proves these contracts statically across a polyglot codebase.

## Languages

- **Python** — full-featured (functions, classes, decorators, attribute reads, imports)
- **TypeScript** — functions, arrow/expression bindings, classes, methods, named/namespace/default imports, receiver-type tracking
- **Go** — functions, methods, package-qualified imports, receiver-type tracking
- **Java** — classes, methods, constructors, imports, receiver-type tracking

## Quick start

```bash
go install github.com/kaeawc/policyguard/cmd/policyguard@latest

# Write a policy
mkdir -p .policies
cat > .policies/pii-before-llm.yaml <<'EOF'
id: pii-before-llm
severity: error
languages: [python]
source:
  any_of:
    - calls: app.users.load_user
    - field_access: "*.email"
sink:
  any_of:
    - calls: anthropic.messages.create
guard:
  any_of:
    - calls: redactor.redact
    - has_decorator: "@redacted"
message: User PII reaches LLM call without passing through redactor.
fix:
  level: idiomatic
  suggestion: "Wrap the user value in {guard}() before {sink.callee}."
EOF

# Run
policyguard check --policies .policies src/
```

Exits 0 with no findings, 1 on findings (CI-gateable), 2 on configuration errors.

## Policy DSL

```yaml
id: pii-redaction-before-llm
severity: error                # error | warning | info
languages: [python, typescript, go, java]
source:
  any_of:
    - calls: user_repo.get_user             # exact callee FQN
    - calls: "anthropic.*"                  # trailing wildcard
    - field_access: "*.email"               # any access of .email
    - has_decorator: "@public_endpoint"     # function-level marker
sink:
  any_of:
    - calls: anthropic.messages.create
    - calls: openai.chat.completions.create
guard:
  any_of:
    - calls: redactor.redact
    - has_decorator: "@redacted"
message: "User PII reaches LLM call without passing through redactor."
fix:
  level: idiomatic              # cosmetic | idiomatic | semantic
  suggestion: "Wrap user data with {guard}() before {sink.callee} at {sink.path}:{sink.line}."
```

**Predicates** — `calls`, `field_access`, and `has_decorator`. Each `any_of` predicate must set exactly one matcher kind.

**Fix template placeholders** — `{policy.id}`, `{function}`, `{source.callee}`, `{source.path}`, `{source.line}`, `{sink.callee}`, `{sink.path}`, `{sink.line}`, `{guard}`.

## How the engine works

For each function `F`, build the **closure**: `F` plus every function transitively reachable through the call graph. `F` violates the contract iff its closure contains a source-matching site AND a sink-matching site AND no guard-matching site (or guard decorator). Findings are deduped to **minimal violators** — when `F` calls `G` and both their closures violate, only `G` is reported. Counterexample chains (with file:line per hop) come along for free, so PR comments show the wrapper → helper sequence that introduced the problem.

## Output formats

`policyguard check --format text|json|sarif|markdown`

- **text** — `file:line: [severity] policy-id: source -> sink` plus chain and fix lines
- **json** — stable wire shape, includes source/sink chains and fix
- **sarif** — SARIF 2.1.0 for GitHub code scanning, IDE viewers, etc.
- **markdown** — PR-comment-friendly with clickable file:line links

## GitHub Action

```yaml
- uses: kaeawc/policyguard@v0  # or pin to a tag
  with:
    policies-dir: .policies
    source-dir: src
    lang: python              # python | typescript | go | java
    fail-on-findings: 'true'  # default
    comment-on-pr: 'true'     # posts/updates a marker comment
    upload-sarif: 'true'      # surfaces findings inline on the PR diff
```

Caller workflow needs `permissions: { contents: read, security-events: write }` for SARIF upload to work. The action looks for an existing PR comment with a hidden marker line and updates it in place rather than appending a new one on each push.

## Architecture

- **Go**, tree-sitter for parsing.
- **Cross-file call graph** with closure-based interprocedural analysis.
- **Receiver-type tracking** for Java, Go, and TypeScript so `obj.method()` resolves to the canonical `<type FQN>.method` rather than the variable-name path.
- **Outputs** — text, JSON, SARIF, markdown.
- **Autofix** — `idiomatic`-level suggestion templates today; structured rewrites a future addition.

## Stretch goals

- **Cross-service mode** — accept an OpenAPI / gRPC spec map; trace a call from service A's handler into service B's endpoint and continue the reachability check.
- **Source-of-truth integration** — pull policies from a central registry (each team owns its policies, shared engine enforces them).
- **Counterexample minimization** — when a policy fails, produce the smallest reproducing snippet.
- **Proof export** — emit a machine-readable proof artifact per enforced policy.
- **Apply-mode autofix** — emit unified diffs / rewrite files in place.
- **LSP + MCP servers** — interactive, in-editor policy enforcement.
- **Kotlin support** — Krit handles it; needs a Go binding for tree-sitter-kotlin.

## Why this is the right shape

Policy-as-code exists for infra (OPA, Cedar) but not for application data flow inside polyglot codebases. The bottleneck is having a fast, multi-language call-graph engine. The DSL keeps policies legible to non-engineers; the engine keeps enforcement fast enough for CI.

## Non-goals

- Runtime enforcement (separate concern, complementary).
- Replacing Semgrep or CodeQL — policyguard is narrower and faster, focused specifically on source → guard → sink contracts.
- Inferring policies; users author them. (A future stretch: mine common patterns and suggest policies.)
