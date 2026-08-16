# Coverage

Honest accounting of what Ordeal evaluates today. No inflated numbers.

## Sigma rule coverage

Ordeal evaluates rules through [`bradleyjkemp/sigma-go`](https://github.com/bradleyjkemp/sigma-go),
extended in `internal/engine` to close the two largest modifier gaps without
forking the engine. Measured against a full clone of `SigmaHQ/sigma` (3,780 rule
files), the base engine evaluates **96.8%**; with the extensions below, **~99.4%**.

### Closed by Ordeal (no fork)

| Modifier | Rules | How |
|----------|-------|-----|
| `\|windash` | ~108 | Registered into sigma-go's exported `EventValueModifiers` map. Normalizes alternative dash flag prefixes (`/`, en-dash, em-dash, horizontal bar) back to `-` in flag position only, so URLs and paths are untouched. |
| `Field: null` | ~85 | A rule rewrite (`rewriteNulls`) feeds sigma-go's existing absent-field comparison the `"null"` value it already matches, instead of the raw YAML nil it rejected. |

Both are covered by tests in `internal/engine`, including a URL false-positive
guard and an absent-vs-present distinction.

### Still unsupported

| Construct | Rules | Notes |
|-----------|-------|-------|
| `\|base64offset` | ~5 | Multi-offset OR-expansion; does not fit the scalar modifier model. |
| `\|expand` | ~32 | Needs deployment-time placeholder definitions to test meaningfully. |
| `\|wide`, `\|re` sub-flags, `\|fieldref` | ~8 combined | Long tail; `fieldref` needs event-time cross-field comparison. |
| Sigma v2 correlations | 0 in the current ruleset | Spec'd, effectively unused today. |

A rule that uses an unsupported construct is not silently mis-evaluated: the
engine surfaces the error. Closing the remainder behind the existing
`engine.Engine` interface is tracked in [ROADMAP.md](ROADMAP.md).

## Telemetry input

- Inline events — full support.
- JSON arrays and JSONL / NDJSON — full support.
- EVTX-rendered JSON (SigmaHQ regression shape) and winlogbeat exports — flattened to Sigma taxonomy.
- Raw `.evtx` binary — not yet; convert to JSON first.

## Mutation catalog

Ten semantics-preserving command-line evasions, each mapped to a MITRE ATT&CK
technique or Sigma modifier. Mutation targets attacker-controlled fields only and
never corrupts opaque payloads. The catalog is deliberately conservative: a
finding is a real evasion an operator could use, not a theoretical one.

## Test coverage of Ordeal itself

Every package carries unit tests. The command tree is covered by end-to-end
golden scripts (`testscript`), and the suite loader is fuzzed. CI runs the full
suite with the race detector on Linux, macOS, and Windows.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
