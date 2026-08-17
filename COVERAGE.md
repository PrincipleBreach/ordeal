# Coverage

Honest accounting of what Ordeal evaluates today. No inflated numbers.

## Sigma rule coverage

Ordeal evaluates rules through [`bradleyjkemp/sigma-go`](https://github.com/bradleyjkemp/sigma-go),
extended in `internal/engine` to close modifier gaps without forking the engine.

### Measured against the live corpus

Numbers below are measured, not estimated, against a shallow clone of
`SigmaHQ/sigma` (2026-08-18): **3,132 single detection rules** (correlation and
non-detection files excluded). Each rule is compiled with Ordeal's engine and
evaluated against a trivial probe event.

| Outcome | Rules | Share |
|---------|-------|-------|
| Evaluate cleanly | 3,025 | **96.6%** |
| Need a `placeholders:` definition (`\|expand`, `%name%`) | 25 | 0.8% |
| Need a field-shaped event (`\|cidr`, numeric) — supported, probe artifact | ~78 | 2.5% |
| Genuinely unsupported construct (`\|fieldref`) | 4 | **0.1%** |

Excluding placeholder rules (which need per-deployment values) and probe
artifacts (the rule's constructs are supported; the synthetic event just lacked
the field), **only 4 rules use a construct Ordeal cannot evaluate.**

### Closed by Ordeal (no fork)

`\|windash` (including the canonical `\|contains\|windash` ordering that SigmaHQ
uses and sigma-go otherwise rejects), `Field: null`, `\|base64offset`, `\|wide` /
`\|utf16le`, `\|re` sub-flags (`i`/`m`/`s`), and `\|expand` (via the
`placeholders:` map). Each is covered by tests in `internal/engine`, including a
URL false-positive guard, an absent-vs-present distinction, the base64offset
vector, and the windash-ordering regression.

### Still unsupported

`\|fieldref` (4 rules) compares two fields of the same event at match time. No
exported hook exposes the event to a modifier, so closing it needs evaluator-level
work behind the existing `engine.Engine` interface. A rule using an unsupported
construct is not silently mis-evaluated — the engine surfaces the error.

## Telemetry input

- Inline events — full support.
- JSON arrays and JSONL / NDJSON — full support.
- EVTX-rendered JSON (SigmaHQ regression shape) and winlogbeat exports — flattened to Sigma taxonomy.
- Raw `.evtx` binary — not yet; convert to JSON first.

## Mutation catalog

41 semantics-preserving command-line evasions across Windows, Linux, and macOS,
each mapped to a MITRE ATT&CK technique or Sigma modifier and carrying a
remediation hint. Families: Windows command-token, windash, path, cmd.exe,
network/URL, PowerShell; Linux/macOS shell; macOS-specific.

Mutation is **platform-gated** on the rule's logsource product, so a Windows
caret or PowerShell evasion is never reported against a Linux or macOS rule (and
vice versa). URL and IP rewrites are platform-agnostic. Mutation targets
attacker-controlled fields only, never corrupts opaque payloads, and scores per
technique, not per variant.

The Linux/macOS shell mutators respect one hard truth: Linux telemetry (auditd,
Sysmon-for-Linux) logs post-expansion argv, so shell obfuscation only survives
inside a literal interpreter `-c` payload (`bash -c "..."`, cron, systemd,
webshells). Those mutators fire only there, and `$IFS`/brace forms are gated by
the payload's interpreter (bash vs zsh). The catalog is deliberately
conservative: a finding is a real evasion an operator could use, not a
theoretical one. Run `ordeal list mutators` for the live list.

## Test coverage of Ordeal itself

Every package carries unit tests. The command tree is covered by end-to-end
golden scripts (`testscript`), and the suite loader is fuzzed. CI runs the full
suite with the race detector on Linux, macOS, and Windows.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
