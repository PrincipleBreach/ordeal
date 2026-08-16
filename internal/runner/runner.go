// Package runner executes test suites and adversarial mutation runs.
//
// It is the orchestration layer: it resolves and parses the Sigma rule for a
// suite, compiles it with the chosen engine, then either asserts the declared
// cases (RunTests) or subjects each matching positive case to the mutation
// catalog and records which evasions slip past (RunMutations).
package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/principlebreach/ordeal/internal/engine"
	"github.com/principlebreach/ordeal/internal/mutate"
	"github.com/principlebreach/ordeal/internal/testcase"
)

// Runner executes suites against an engine.
type Runner struct {
	Engine engine.Engine
}

// New returns a Runner backed by the given engine.
func New(eng engine.Engine) *Runner { return &Runner{Engine: eng} }

// --- Unit testing --------------------------------------------------------

// CaseResult is the outcome of one declared test case.
type CaseResult struct {
	Suite             string   `json:"suite"`
	Rule              string   `json:"rule"`
	Name              string   `json:"name"`
	Expected          bool     `json:"expected"`
	Actual            bool     `json:"actual"`
	Pass              bool     `json:"pass"`
	MissingSelections []string `json:"missing_selections,omitempty"`
	Err               error    `json:"-"`
	ErrMsg            string   `json:"error,omitempty"`
}

// TestReport aggregates case results across suites.
type TestReport struct {
	Cases []CaseResult `json:"cases"`
}

// Passed and Failed count case outcomes.
func (r TestReport) Passed() int { return r.count(true) }
func (r TestReport) Failed() int { return r.count(false) }

func (r TestReport) count(pass bool) int {
	n := 0
	for _, c := range r.Cases {
		if c.Pass == pass {
			n++
		}
	}
	return n
}

// OK reports whether every case passed.
func (r TestReport) OK() bool { return r.Failed() == 0 }

// RunTests asserts every declared case in every suite.
func (rn *Runner) RunTests(ctx context.Context, suites []*testcase.Suite) (TestReport, error) {
	var report TestReport
	for _, s := range suites {
		matcher, err := rn.compile(s)
		if err != nil {
			report.Cases = append(report.Cases, CaseResult{
				Suite: s.Path, Rule: s.Rule, Name: "<compile>", Err: err, ErrMsg: err.Error(),
			})
			continue
		}
		for _, c := range s.Cases {
			report.Cases = append(report.Cases, rn.assertCase(ctx, s, matcher, c))
		}
	}
	return report, nil
}

func (rn *Runner) assertCase(ctx context.Context, s *testcase.Suite, m engine.Matcher, c testcase.Case) CaseResult {
	res := CaseResult{Suite: s.Path, Rule: s.Rule, Name: c.Name, Expected: c.ExpectMatch()}
	v, err := m.Match(ctx, c.Event)
	if err != nil {
		res.Err = err
		res.ErrMsg = err.Error()
		return res
	}
	res.Actual = v.Matched
	res.Pass = v.Matched == c.ExpectMatch()
	// Verify asserted selections actually fired.
	if res.Pass && c.ExpectMatch() {
		for _, want := range c.Selections {
			if !v.Selections[want] {
				res.MissingSelections = append(res.MissingSelections, want)
			}
		}
		if len(res.MissingSelections) > 0 {
			res.Pass = false
		}
	}
	return res
}

// --- Adversarial mutation ------------------------------------------------

// Evasion is a single mutation that stopped the rule from firing.
type Evasion struct {
	Mutator string `json:"mutator"`
	Field   string `json:"field"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Note    string `json:"note"`
}

// Resilience records how one positive case held up under mutation.
type Resilience struct {
	Suite           string    `json:"suite"`
	Rule            string    `json:"rule"`
	CaseName        string    `json:"case"`
	BaselineMatched bool      `json:"baseline_matched"`
	Attempted       int       `json:"attempted"`
	Survived        int       `json:"survived"`
	Evaded          []Evasion `json:"evaded"`
}

// Score is the fraction of mutations the rule still caught (1.0 == no evasions).
func (r Resilience) Score() float64 {
	if r.Attempted == 0 {
		return 1
	}
	return float64(r.Survived) / float64(r.Attempted)
}

// MutationReport aggregates resilience across suites.
type MutationReport struct {
	Rules []Resilience `json:"rules"`
}

// TotalEvasions counts evasions across all rules.
func (r MutationReport) TotalEvasions() int {
	n := 0
	for _, res := range r.Rules {
		n += len(res.Evaded)
	}
	return n
}

// OK reports whether no rule was evaded.
func (r MutationReport) OK() bool { return r.TotalEvasions() == 0 }

// RunMutations subjects every matching positive case to the mutation catalog.
func (rn *Runner) RunMutations(ctx context.Context, suites []*testcase.Suite) (MutationReport, error) {
	var report MutationReport
	for _, s := range suites {
		if !s.MutateEnabled() {
			continue
		}
		matcher, err := rn.compile(s)
		if err != nil {
			return report, fmt.Errorf("compiling %s: %w", s.Path, err)
		}
		for _, c := range s.Cases {
			if !c.ExpectMatch() {
				continue // only positive detections can be evaded
			}
			report.Rules = append(report.Rules, rn.mutateCase(ctx, s, matcher, c))
		}
	}
	return report, nil
}

func (rn *Runner) mutateCase(ctx context.Context, s *testcase.Suite, m engine.Matcher, c testcase.Case) Resilience {
	res := Resilience{Suite: s.Path, Rule: s.Rule, CaseName: c.Name}

	base, err := m.Match(ctx, c.Event)
	if err != nil || !base.Matched {
		// If the baseline positive does not fire, mutation is meaningless; the
		// unit test run already flags this as a failure.
		return res
	}
	res.BaselineMatched = true

	fields := mutate.StringFields(c.Event)
	for _, variant := range mutate.Generate(c.Event, fields) {
		res.Attempted++
		v, err := m.Match(ctx, variant.Event)
		if err != nil {
			continue
		}
		if v.Matched {
			res.Survived++
			continue
		}
		res.Evaded = append(res.Evaded, Evasion{
			Mutator: variant.Mutator,
			Field:   variant.Field,
			Before:  variant.Before,
			After:   variant.After,
			Note:    variant.Note,
		})
	}
	sort.Slice(res.Evaded, func(i, j int) bool {
		if res.Evaded[i].Field != res.Evaded[j].Field {
			return res.Evaded[i].Field < res.Evaded[j].Field
		}
		return res.Evaded[i].Mutator < res.Evaded[j].Mutator
	})
	return res
}

// --- Rule loading --------------------------------------------------------

func (rn *Runner) compile(s *testcase.Suite) (engine.Matcher, error) {
	base := filepath.Dir(s.Path)
	ruleBytes, err := os.ReadFile(filepath.Join(base, s.Rule))
	if err != nil {
		return nil, fmt.Errorf("reading rule: %w", err)
	}
	rule, err := sigma.ParseRule(ruleBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing rule: %w", err)
	}
	var configs []sigma.Config
	for _, cfgPath := range s.Configs {
		cfgBytes, err := os.ReadFile(filepath.Join(base, cfgPath))
		if err != nil {
			return nil, fmt.Errorf("reading config %s: %w", cfgPath, err)
		}
		cfg, err := sigma.ParseConfig(cfgBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing config %s: %w", cfgPath, err)
		}
		configs = append(configs, cfg)
	}
	return rn.Engine.Compile(rule, configs...)
}
