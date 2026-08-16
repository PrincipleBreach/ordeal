# Contributing to Ordeal

Ordeal is built by [Principle Breach](https://principlebreach.com). Contributions are welcome.

## Ground rules

- Every change keeps `go test ./...`, `go vet ./...`, and `gofmt -s` green.
- New behaviour ships with a test. Bug fixes ship with the failing test first.
- One format, one flag, one way to do a thing. Resist adding a second.

## Adding a mutator

The mutation catalog is the heart of the tool. A mutator encodes one real,
semantics-preserving evasion: the mutated command must do the same thing on the
host, and only its surface form may change. If a mutation changes behaviour, it
is a false finding and does not belong.

1. Implement the `mutate.Mutator` interface in `internal/mutate/mutate.go`.
2. Add it to `Catalog()`.
3. Add a table test proving the transform and one proving it is a no-op when it
   does not apply.
4. Cite the technique in the doc comment (ArgFuscator, DOSfuscation, LOLBAS,
   the Sigma `windash` modifier, and MITRE ATT&CK T1027 are good anchors).

## Local development

```bash
make test      # unit tests
make run       # assert the example rules fire
make demo      # attack the example rules
```

## Reporting a security issue

Do not open a public issue for a vulnerability in Ordeal itself. Email
security@principlebreach.com.
