// Package testcase loads and validates Ordeal test suites.
//
// A suite is a sidecar YAML file (<rule>.test.yml) that pairs a Sigma rule with
// example events and the expected verdict. It is intentionally close to the
// SigmaHQ rule aesthetic: scannable, reviewable in a pull request, one format
// only, and strict about unknown keys so a typo'd field is an error rather than
// a silently-skipped assertion.
package testcase

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Suite is one <rule>.test.yml file.
type Suite struct {
	// Rule is the path to the Sigma rule under test, relative to the suite file.
	Rule string `yaml:"rule"`
	// Configs are optional sigma-go field-mapping config paths, relative to the
	// suite file, applied in order.
	Configs []string `yaml:"config"`
	// Cases are the individual test cases.
	Cases []Case `yaml:"cases"`
	// Mutate, when false, opts this suite out of adversarial mutation testing.
	// Defaults to true.
	Mutate *bool `yaml:"mutate"`

	// Path is the on-disk location of this suite, set by the loader.
	Path string `yaml:"-"`
}

// Case is a single expectation: an event plus the verdict it should produce.
type Case struct {
	Name  string                 `yaml:"name"`
	Event map[string]interface{} `yaml:"event"`
	// Match is the expected verdict. Defaults to true when omitted, since
	// positive cases dominate.
	Match *bool `yaml:"match"`
	// Selections optionally asserts which named selections must have matched.
	Selections []string `yaml:"selections"`
}

// ExpectMatch reports the expected verdict, defaulting to true.
func (c Case) ExpectMatch() bool {
	if c.Match == nil {
		return true
	}
	return *c.Match
}

// MutateEnabled reports whether adversarial mutation should run for this suite.
func (s Suite) MutateEnabled() bool {
	if s.Mutate == nil {
		return true
	}
	return *s.Mutate
}

// Load reads and validates a single suite file.
func Load(path string) (*Suite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // reject unknown keys: a typo'd assertion must fail loudly
	var s Suite
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.Path = path
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func (s Suite) validate() error {
	if s.Rule == "" {
		return fmt.Errorf("missing required field 'rule'")
	}
	if len(s.Cases) == 0 {
		return fmt.Errorf("suite has no cases")
	}
	seen := map[string]bool{}
	for i, c := range s.Cases {
		if c.Name == "" {
			return fmt.Errorf("cases[%d]: every case must have a 'name'", i)
		}
		if seen[c.Name] {
			return fmt.Errorf("cases[%d]: duplicate case name %q", i, c.Name)
		}
		seen[c.Name] = true
		if len(c.Event) == 0 {
			return fmt.Errorf("case %q: 'event' must not be empty", c.Name)
		}
		if len(c.Selections) > 0 && !c.ExpectMatch() {
			return fmt.Errorf("case %q: 'selections' cannot be asserted when match is false", c.Name)
		}
	}
	return nil
}
