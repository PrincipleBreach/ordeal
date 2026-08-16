# CLAUDE.md

Guidance for Claude Code and other agents working in this repository.

## What this is

Ordeal is an adversarial test harness for Sigma detection rules. It asserts a
rule fires on the events it should (`ordeal run`), then attacks the rule with
semantics-preserving command-line evasions and reports what slips past
(`ordeal mutate`). Written in Go, single static binary, MIT licensed.

## Build, test, run

```bash
make test        # go test ./... — unit, golden CLI (testscript), and fuzz tests
make build       # build the ordeal binary
make run         # assert the example rules fire
make demo        # attack the example rules
go test -race ./...   # what CI runs
```

Before any commit: `gofmt -s -w .`, `go vet ./...`, and `go test ./...` must all
be clean. CI runs the full suite with the race detector on Linux, macOS, and
Windows.

## Layout

```
cmd/ordeal/         thin main + golden CLI scripts (testdata/script/*.txtar)
internal/
  cli/              cobra command tree: run, mutate, lint, list
  engine/           Sigma evaluation behind an Engine interface (wraps sigma-go)
    engine.go       Engine/Matcher/Verdict, Compile options
    modifiers.go    modifier gaps closed without forking (windash, null, base64offset, wide, re, expand)
  mutate/           the evasion catalog — the core value
    mutate.go       Mutator interface, registry, field classification, shared helpers
    mut_*.go        one file per mutator family (network, path, cmd, ps_resolve, ps_string)
  testcase/         *.test.yml loader, strict validation, discovery
  dataset/          load telemetry (JSON/JSONL/EVTX-rendered/winlog) into events
  runner/           orchestrates run + mutate; per-technique scoring
  report/           human (lipgloss), JSON, JUnit output
examples/           real Sigma rules with suites, used as an acceptance test
docs/               test-format, mutator catalog, writing-suites, ci
```

## The mutation catalog is the moat

Mutators live in `internal/mutate`. Each is a small type implementing:

```go
type Mutator interface {
    Name() string        // stable kebab-case id, used on the CLI and in reports
    Technique() string   // MITRE ATT&CK id or Sigma modifier
    Describe() string    // one-line description
    Remediation() string // the blue-team fix, printed on a finding
    Apply(value string) []Result
}
```

To add a mutator: create or extend a `mut_<family>.go`, implement the interface,
and `register(yourMutator{})` in that file's `init()`. It is picked up by the
catalog, `list mutators`, `--only/--skip`, and scoring automatically. Add a
table test.

Two non-negotiable rules for any mutator — a violation produces false findings,
which is worse than a missing mutator:

1. **Deterministic and semantics-preserving.** `Apply` is a pure function of its
   input (no randomness, no time, no I/O). The mutated command must do exactly
   the same thing on the host; only its text changes. If you cannot prove the
   equivalence, gate the technique out (`return nil`) rather than emit it.
2. **Never corrupt attacker payloads or the wrong fields.** Token-level mutators
   must skip opaque payload blobs (`isOpaque`). Mutation only ever touches
   attacker-controlled command text (`Classify` → `ClassCommand`), never a
   kernel-resolved field like `Image`.
3. **Declare the platform.** A mutator that is not Windows-only implements
   `Platforms() []Platform` (`Windows`/`Linux`/`MacOS`/`AnyOS`; default is
   Windows). Mutation is gated to the rule's logsource product so a Windows
   evasion never fires against a Linux rule. Linux/macOS telemetry logs
   post-expansion argv, so shell mutators (`mut_nix.go`) fire only inside a
   literal `-c` payload via `nixPayload`, and `$IFS`/brace forms check the
   payload interpreter (not zsh / bash-only).

Scoring is per technique, not per variant: a mutator that defeats a rule through
ten variants counts once.

## Engine coverage

The Sigma engine is `bradleyjkemp/sigma-go`, extended in `internal/engine`
through its own extension points (exported modifier maps, a rule-AST rewrite, the
placeholder-expander hook) rather than a fork. See `COVERAGE.md`. Keep it behind
the `Engine` interface so a future fork or a differential oracle stays a drop-in.

## Documentation conventions

- No emoji anywhere — in code, docs, or program output. Use `—`, `·`, `/`, `->`.
- Terse, declarative, present tense. American spelling. No hype words.
- Every Markdown file ends with the footer:
  `<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>`
- Keep internal planning out of the repo. Roadmaps and strategy do not ship.

## Commits

Conventional Commits (`feat(scope):`, `fix:`, `docs:`, `test:`, `refactor:`).
One logical change per commit. Never add AI or tool attribution to commit
messages or PR bodies.
