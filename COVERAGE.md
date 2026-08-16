# Coverage

Honest accounting of what Ordeal evaluates today. No inflated numbers.

## Sigma rule coverage

Ordeal evaluates rules through [`bradleyjkemp/sigma-go`](https://github.com/bradleyjkemp/sigma-go).
Measured against a full clone of `SigmaHQ/sigma` (3,780 rule files), that engine
already evaluates **96.8%** of the ruleset. The gaps are shallow and known:

| Unsupported today | Rules affected | Notes |
|-------------------|----------------|-------|
| `\|windash` modifier | ~108 | Rules that already model the dash-substitution Ordeal mutates. |
| `Field: null` | ~85 | Absent-field matching. |
| `\|base64offset`, `\|wide`, `\|re` sub-flags, `\|fieldref`, `\|expand` | ~45 combined | Long-tail value modifiers. |
| Sigma v2 correlations | 0 in the current ruleset | Spec'd, effectively unused today. |

A rule that uses an unsupported construct is not silently mis-evaluated: the
engine surfaces it. Closing these gaps behind the existing `engine.Engine`
interface — by vendoring and extending the evaluator — is the next milestone
(see [ROADMAP.md](ROADMAP.md)).

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

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research and advisory. Part of <a href="https://adversaryholdings.com">Adversary Holdings</a>.</sub>
