# Running Ordeal in CI

Ordeal is built to be a merge gate. It is a single static binary, it reads only
the files you point it at, it makes no network calls, and it exits with codes CI
can act on.

Two gates, and they mean different things:

- `ordeal run` — the rule fires on its declared cases. Blocking. A red run means
  the rule is wrong.
- `ordeal mutate` — the rule survives the evasion catalog. Blocking on a mature
  corpus, advisory on a new one. A red mutate means the rule is evadable.

<!-- ------------------------------------------------------------ -->

## GitHub Action

```yaml
name: detections

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  ordeal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: principlebreach/ordeal@v1
        with:
          paths: ./rules
          mutate: "true"
```

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `paths` | `.` | Space-separated files or directories to scan for `*.test.yml` suites. |
| `mutate` | `"false"` | Run adversarial mutation and fail the job if any detection is evaded. |
| `version` | `"latest"` | Ordeal version to install — a git ref such as `v1.2.0`, or `latest`. |

Inputs are strings. Quote `"true"` and `"false"`.

The action is a composite that installs Ordeal with `go install` and runs two
steps: `ordeal run <paths> --format junit`, then `ordeal mutate <paths>` when
`mutate` is `"true"`. The test report is written to `ordeal-tests.xml` in the
workspace and printed to the log if the step fails.

Pin the version on anything that gates a merge:

```yaml
      - uses: principlebreach/ordeal@v1
        with:
          paths: ./rules ./contrib/rules
          version: v1.2.0
```

### Multiple paths

`paths` is passed through to the CLI unquoted, so several paths separate with
spaces. Directories are walked recursively; files are used as given.

### Staged adoption

On an existing corpus, mutation will be red on day one. Land the run gate first
and keep mutation visible but non-blocking until the backlog is worked down:

```yaml
      - uses: principlebreach/ordeal@v1
        with:
          paths: ./rules
      - name: Adversarial mutation (advisory)
        continue-on-error: true
        run: ordeal mutate ./rules
```

Flip it to `mutate: "true"` once the score is where you want it. Making it
blocking is the point — an advisory gate that stays red forever is noise.

<!-- ------------------------------------------------------------ -->

## Raw Binary

Any CI system. No action required.

```bash
go install github.com/principlebreach/ordeal/cmd/ordeal@latest
ordeal run ./rules --format junit > ordeal-tests.xml
ordeal mutate ./rules
```

Release archives are attached to each GitHub release for linux, darwin, and
windows on amd64 and arm64, with `checksums.txt` signed by cosign:

```bash
VERSION=1.2.0
curl -sSL -o ordeal.tar.gz \
  "https://github.com/principlebreach/ordeal/releases/download/v${VERSION}/ordeal_${VERSION}_linux_amd64.tar.gz"
tar -xzf ordeal.tar.gz ordeal
./ordeal run ./rules
```

### GitLab CI

```yaml
detections:
  image: golang:1.26
  script:
    - go install github.com/principlebreach/ordeal/cmd/ordeal@latest
    - ordeal run ./rules --format junit > ordeal-tests.xml
    - ordeal mutate ./rules
  artifacts:
    when: always
    reports:
      junit: ordeal-tests.xml
```

### Container

The repository ships a multi-stage `Dockerfile` producing a distroless image with
no shell. Build it and mount the rules read-only:

```bash
docker build -t ordeal .
docker run --rm -v "$PWD/rules:/rules:ro" ordeal run /rules
```

The entrypoint is the binary, so arguments pass straight through.

### Pre-commit

```bash
ordeal run ./rules || exit 1
```

Keep mutation out of the pre-commit path. It is slower and its findings deserve
review, not a blocked commit.

<!-- ------------------------------------------------------------ -->

## Output Formats

| Format | `run` | `mutate` | Use |
| --- | --- | --- | --- |
| `human` | yes | yes | Default. Color is dropped automatically on a non-TTY, so CI logs stay clean. |
| `json` | yes | yes | Machine consumption — dashboards, score tracking, custom gates. |
| `junit` | yes | — | CI test reporting. |

```bash
ordeal run ./rules --format json
ordeal mutate ./rules --format json
```

`mutate` has no JUnit renderer; an evasion is a finding, not a test failure. Use
`--format json` to feed mutation results anywhere structured.

`mutate` also takes `--only` and `--skip` to restrict the catalog, which is how
you stage a new mutator into an existing pipeline:

```bash
ordeal mutate ./rules --skip case-flip          # backend is case-insensitive
ordeal mutate ./rules --only windash            # working one gap at a time
```

## JUnit Output

`--format junit` writes a `testsuites` document to stdout. One `testsuite` per
suite file, one `testcase` per declared case, with a `failure` element carrying the
expected-versus-actual detail and an `error` element for suites that failed to
compile.

```bash
ordeal run ./rules --format junit > ordeal-tests.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" failures="1">
  <testsuite name="rules/certutil_download/rule.test.yml">
    <testcase name="certutil urlcache download fires"></testcase>
    <testcase name="certutil dump is benign">
      <failure message="expected match=false, got match=true []"></failure>
    </testcase>
  </testsuite>
</testsuites>
```

Redirect to a file rather than piping — the shell must capture stdout before the
non-zero exit propagates. To surface the report in a GitHub pull request:

```yaml
      - name: Detection tests
        run: ordeal run ./rules --format junit > ordeal-tests.xml
      - name: Publish results
        if: always()
        uses: mikepenz/action-junit-report@v4
        with:
          report_paths: ordeal-tests.xml
```

`if: always()` matters. Without it the publish step is skipped on the failure you
most wanted to see.

## Tracking the Score

`mutate --format json` gives per-case resilience — `attempted`, `survived`, and
the full `evaded` list with mutator, field, note, and mutated value. Two useful
gates beyond pass/fail:

```bash
# Fail if any rule scores under 80%.
ordeal mutate ./rules --format json \
  | jq -e 'all(.rules[]; .attempted == 0 or (.survived / .attempted) >= 0.8)'
```

```bash
# Report the weakest rules first.
ordeal mutate ./rules --format json \
  | jq -r '.rules | sort_by(.survived / .attempted)
           | .[] | "\(.case)\t\(.survived)/\(.attempted)"'
```

Track the aggregate across commits. The number that matters is the direction it
moves, not its absolute value on any one day.

## Exit Codes

| Code | Meaning | CI action |
| --- | --- | --- |
| `0` | Everything passed. No case failed, nothing evaded. | Merge. |
| `1` | Findings. A case failed, or a detection was evaded. | Block. Fix the rule. |
| `2` | Usage error. Bad path, malformed suite, unknown key, unparseable rule. | Block. Fix the pipeline or the suite. |

The split between `1` and `2` is deliberate: `1` means your detections are wrong,
`2` means the invocation is wrong. Do not collapse them. A pipeline that treats
every non-zero the same way will report a typo'd YAML key as a detection gap for
weeks.

When `run --mutate` is used, a failure in either stage exits `1`.

## Coverage Gate

`lint` catches what the test run cannot: rules with no suite at all.

```bash
ordeal lint ./rules
```

```
ERROR  rules/psexec/rule.test.yml  rule not found: psexec.yml
WARN   rules/wmic_process/rule.yml  no test suite
WARN   rules/mshta/rule.test.yml  no negative case

1 errors, 2 warnings
```

Findings are split by severity. `ERROR` is a broken pairing — a suite that cannot
load, or one pointing at a rule that is not on disk. Nothing is being tested.
`WARN` is a coverage gap: the harness runs, but proves less than the author
intended.

Only errors fail the command. `lint` exits `1` when there is at least one error,
`0` when there are warnings but no errors. To gate on warnings too, read the
counts:

```bash
ordeal lint ./rules --format json | jq -e '.errors == 0 and .warnings == 0'
```

Run `lint` before `run` — a rule with no suite passes every test report ever
generated.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research and advisory. Part of <a href="https://adversaryholdings.com">Adversary Holdings</a>.</sub>
