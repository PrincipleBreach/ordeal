package testcase

import (
	"os"
	"path/filepath"
	"testing"
)

func load(t *testing.T, body string) (*Suite, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "r.test.yml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestMatchDefaultsToTrue(t *testing.T) {
	s, err := load(t, "rule: r.yml\ncases:\n  - name: a\n    event: {A: b}\n")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Cases[0].ExpectMatch() {
		t.Error("match should default to true")
	}
	if !s.MutateEnabled() {
		t.Error("mutate should default to true")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, err := load(t, "rule: r.yml\ntypo: 1\ncases:\n  - name: a\n    event: {A: b}\n")
	if err == nil {
		t.Fatal("expected error on unknown top-level key")
	}
}

func TestEventAndDatasetMutuallyExclusive(t *testing.T) {
	_, err := load(t, "rule: r.yml\ncases:\n  - name: a\n    event: {A: b}\n    dataset: d.json\n")
	if err == nil {
		t.Fatal("expected error when both event and dataset are set")
	}
}

func TestOneOfEventOrDatasetRequired(t *testing.T) {
	_, err := load(t, "rule: r.yml\ncases:\n  - name: a\n")
	if err == nil {
		t.Fatal("expected error when neither event nor dataset is set")
	}
}

func TestSelectionsRequirePositiveInline(t *testing.T) {
	_, err := load(t, "rule: r.yml\ncases:\n  - name: a\n    event: {A: b}\n    match: false\n    selections: [s]\n")
	if err == nil {
		t.Fatal("expected error: selections on a negative case")
	}
	_, err = load(t, "rule: r.yml\ncases:\n  - name: a\n    dataset: d.json\n    selections: [s]\n")
	if err == nil {
		t.Fatal("expected error: selections on a dataset case")
	}
}

func TestDuplicateCaseNameRejected(t *testing.T) {
	_, err := load(t, "rule: r.yml\ncases:\n  - name: a\n    event: {A: b}\n  - name: a\n    event: {A: c}\n")
	if err == nil {
		t.Fatal("expected error on duplicate case name")
	}
}

func TestMissingRuleRejected(t *testing.T) {
	_, err := load(t, "cases:\n  - name: a\n    event: {A: b}\n")
	if err == nil {
		t.Fatal("expected error when rule is missing")
	}
}
