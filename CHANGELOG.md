# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `dataset:` case field — load events from a JSON / JSONL / EVTX-rendered /
  winlogbeat file instead of declaring them inline, so a suite can assert against
  captured telemetry.
- `ordeal lint` — reports untested rules, dangling suite references, and suites
  missing a positive or negative case.
- `ordeal list mutators` — prints the evasion catalog with the ATT&CK technique
  each mutator models.
- `powershell-tick` mutator (backtick escape). Every mutator now carries an
  ATT&CK / Sigma-modifier anchor, shown by `list mutators`.
- `--only` and `--skip` flags on `ordeal mutate` to restrict the catalog.
- Engine support for the `|windash`, `Field: null`, `|base64offset`, `|wide`,
  `|re` sub-flag, and `|expand` modifiers, closing nearly every coverage gap
  without forking sigma-go. Raises evaluated coverage from ~96.8% to ~99.9%
  (only `|fieldref` remains). See [COVERAGE.md](COVERAGE.md).
- `placeholders:` suite key — defines values for `%name%` placeholders so rules
  using `|expand` or bare placeholders can be evaluated.
- Example corpus of LOLBin rules with suites (rundll32, regsvr32, mshta,
  bitsadmin, wmic, schtasks, net user, defender tampering, rundll32 no-cli).

### Changed

- Mutation is now field-aware: only attacker-controlled fields (`CommandLine`)
  are mutated, not kernel-resolved fields (`Image`), removing findings that did
  not model a real evasion.

### Fixed

- Token and case mutators no longer reshape opaque payloads (a base64 blob is
  left byte-for-byte intact), which previously produced evasions that would not
  actually execute.

## [0.1.0] - 2026-08-17

Initial release. Ordeal asserts that a Sigma rule fires on the events it should,
then attacks the rule with known evasions and reports what slips past.

### Added

- `ordeal run <paths>` — loads Sigma rules and their sidecar `<rule>.test.yml`
  suites, asserts each case fires or does not (`match: true` / `false`), and can
  assert which named selections fired (`selections: [..]`). Directories are
  walked recursively for `*.test.yml`.
- `ordeal mutate <paths>` — for every positive case that fires, applies a catalog
  of semantics-preserving command-line evasions and reports each mutation that
  stops the rule from firing. Scores each case as `survives X/N evasions`.
- Mutator catalog: `flag-abbreviation`, `windash`, `caret-insertion`,
  `quote-insertion`, `env-indirection`, `forward-slash-path`, `trailing-dot`,
  `whitespace-padding`, `case-flip`.
- Rule evaluation through [`bradleyjkemp/sigma-go`](https://github.com/bradleyjkemp/sigma-go),
  with optional Sigma field-mapping configs per suite (`config:`).
- Suite loader with strict unknown-key rejection, duplicate case-name detection,
  and `mutate: false` to opt a suite out of mutation.
- Output formats: `human`, `json`, and `junit`. Color is dropped on a non-TTY.
- Exit codes: `0` pass, `1` findings, `2` usage error.
- GitHub Action (`principlebreach/ordeal@v1`) with `paths`, `mutate`, and
  `version` inputs.
- Single static binary for linux, darwin, and windows on amd64 and arm64, with
  signed checksums and SBOMs.

[Unreleased]: https://github.com/principlebreach/ordeal/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/principlebreach/ordeal/releases/tag/v0.1.0

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
