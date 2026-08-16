// Package lint audits a detection-rules tree for test hygiene problems.
//
// Ordeal can only attack what it can see. A rule with no sidecar suite is
// invisible to the runner, a suite pointing at a moved rule fails silently in
// review, and a suite with only positive cases proves nothing about false
// positives. The linter reports those gaps before they reach CI, where they
// would otherwise show up as an empty pass.
//
// Findings are advisory (Warn) or blocking (Error). Output is deterministic:
// findings are sorted by path, then severity, then message, so the report can
// be diffed between runs.
package lint

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/principlebreach/ordeal/internal/testcase"
)

// Severity classifies how much a finding matters.
type Severity int

const (
	// Error marks a broken pairing: a suite that cannot be loaded or that
	// points at a rule which is not on disk. Nothing is being tested.
	Error Severity = iota
	// Warn marks a coverage gap: the harness runs, but proves less than the
	// author probably intended.
	Warn
)

// String returns the lowercase severity name, "error" or "warn".
func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warn:
		return "warn"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes the severity as its name rather than its ordinal, so the
// JSON report stays readable and survives reordering of the constants.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Finding is a single hygiene problem found in the rules tree.
type Finding struct {
	// Severity is Error for a broken pairing, Warn for a coverage gap.
	Severity Severity `json:"severity"`
	// Path is the file the finding is reported against, as it was walked: the
	// suite for suite problems, the rule for coverage problems.
	Path string `json:"path"`
	// Rule identifies the detection concerned: its Sigma title when the rule
	// file could be parsed, otherwise the raw reference from the suite. It is
	// empty when neither is available.
	Rule string `json:"rule,omitempty"`
	// Message is a one-line description in lowercase, without the path.
	Message string `json:"message"`
}

// Report is the result of a lint run.
type Report struct {
	// Findings are sorted by path, then severity, then message.
	Findings []Finding `json:"findings"`
}

// Errors counts findings with Error severity.
func (r Report) Errors() int { return r.count(Error) }

// Warnings counts findings with Warn severity.
func (r Report) Warnings() int { return r.count(Warn) }

// OK reports whether the run is clean enough to proceed. Warnings do not fail
// a lint run; only errors do.
func (r Report) OK() bool { return r.Errors() == 0 }

func (r Report) count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

func (r *Report) add(f Finding) { r.Findings = append(r.Findings, f) }

// Run audits the given files and directories. Directories are walked
// recursively; dotted directories are skipped. Files that are neither YAML nor
// parseable as a Sigma rule are ignored, so pointing Run at a mixed repository
// is safe.
//
// An error is returned only for unusable input, such as a path that does not
// exist. Problems found in the tree are reported as findings, not errors.
func Run(paths []string) (Report, error) {
	suitePaths, rulePaths, err := collect(paths)
	if err != nil {
		return Report{}, err
	}

	// Index the Sigma rules first: suite findings quote the rule title when
	// the target parses, which reads better than a bare relative path.
	titles := make(map[string]string, len(rulePaths))
	sigmaRules := make([]string, 0, len(rulePaths))
	for _, p := range rulePaths {
		title, ok := sigmaRule(p)
		if !ok {
			continue
		}
		titles[canonical(p)] = title
		sigmaRules = append(sigmaRules, p)
	}

	var rep Report
	covered := make(map[string]bool, len(suitePaths))
	for _, p := range suitePaths {
		suite, err := testcase.Load(p)
		if err != nil {
			// Load prefixes its errors with the path; the finding carries the
			// path separately, so drop the duplicate.
			rep.add(Finding{Severity: Error, Path: p, Message: strings.TrimPrefix(err.Error(), p+": ")})
			continue
		}
		target := filepath.Join(filepath.Dir(p), suite.Rule)
		covered[canonical(target)] = true

		name := suite.Rule
		if title := titles[canonical(target)]; title != "" {
			name = title
		}
		if _, err := os.Stat(target); err != nil {
			rep.add(Finding{Severity: Error, Path: p, Rule: name,
				Message: fmt.Sprintf("rule reference %q does not exist", suite.Rule)})
		}

		var positive, negative int
		for _, c := range suite.Cases {
			if c.ExpectMatch() {
				positive++
			} else {
				negative++
			}
		}
		if positive == 0 {
			rep.add(Finding{Severity: Warn, Path: p, Rule: name,
				Message: "no case expects a match; mutation testing has nothing to attack"})
		}
		if negative == 0 {
			rep.add(Finding{Severity: Warn, Path: p, Rule: name,
				Message: "no case expects a non-match; the rule has no false-positive guard"})
		}
	}

	for _, p := range sigmaRules {
		if covered[canonical(p)] {
			continue
		}
		// A suite may exist by convention but have failed to load, in which
		// case the load error above is the finding worth reporting; do not
		// also call the rule untested.
		sibling := siblingSuite(p)
		if _, err := os.Stat(sibling); err == nil {
			continue
		}
		rep.add(Finding{Severity: Warn, Path: p, Rule: titles[canonical(p)],
			Message: fmt.Sprintf("rule has no test suite; expected %s", filepath.Base(sibling))})
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		switch {
		case a.Path != b.Path:
			return a.Path < b.Path
		case a.Severity != b.Severity:
			return a.Severity < b.Severity
		default:
			return a.Message < b.Message
		}
	})
	return rep, nil
}

// collect expands paths into the YAML files to inspect, partitioned into test
// suites and everything else. Both slices are deduplicated and sorted.
func collect(paths []string) (suites, rules []string, err error) {
	seen := make(map[string]bool)
	add := func(p string) {
		c := canonical(p)
		if seen[c] {
			return
		}
		seen[c] = true
		if strings.HasSuffix(p, testcase.Suffix) {
			suites = append(suites, p)
			return
		}
		rules = append(rules, p)
	}

	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			return nil, nil, err
		}
		if !info.IsDir() {
			if isYAML(root) {
				add(root)
			}
			continue
		}
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			hidden := strings.HasPrefix(d.Name(), ".")
			if d.IsDir() {
				if p != root && hidden {
					return fs.SkipDir
				}
				return nil
			}
			if !hidden && isYAML(p) {
				add(p)
			}
			return nil
		})
		if walkErr != nil {
			return nil, nil, walkErr
		}
	}
	sort.Strings(suites)
	sort.Strings(rules)
	return suites, rules, nil
}

// sigmaRule reports whether path holds a Sigma detection rule, returning its
// title. Field-mapping configs and unrelated YAML fail the detection check and
// are rejected, which is what keeps the untested-rule warning quiet on a mixed
// tree.
func sigmaRule(path string) (title string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	rule, err := sigma.ParseRule(data)
	if err != nil || rule.Title == "" {
		return "", false
	}
	if len(rule.Detection.Searches) == 0 && len(rule.Detection.Conditions) == 0 {
		return "", false
	}
	return rule.Title, true
}

// siblingSuite returns the conventional suite path for a rule file:
// rules/foo.yml pairs with rules/foo.test.yml.
func siblingSuite(rulePath string) string {
	return strings.TrimSuffix(rulePath, filepath.Ext(rulePath)) + testcase.Suffix
}

// canonical normalizes a path for use as a map key, so a rule reached through
// a walk and the same rule named by a suite's rule field compare equal.
func canonical(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}

func isYAML(p string) bool {
	switch filepath.Ext(p) {
	case ".yml", ".yaml":
		return true
	default:
		return false
	}
}

// WriteHuman renders the report as plain text, one finding per line, followed
// by a summary. It is deliberately uncoloured: lint output is read in pull
// requests and CI logs more often than in a terminal.
func (r Report) WriteHuman(w io.Writer) error {
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "%-5s  %s  %s\n", strings.ToUpper(f.Severity.String()), f.Path, f.Message); err != nil {
			return err
		}
	}
	if len(r.Findings) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%d errors, %d warnings\n", r.Errors(), r.Warnings())
	return err
}

// WriteJSON renders the report as pretty-printed JSON. The counts are included
// so a CI step can gate on them without walking the findings.
func (r Report) WriteJSON(w io.Writer) error {
	out := struct {
		Findings []Finding `json:"findings"`
		Errors   int       `json:"errors"`
		Warnings int       `json:"warnings"`
	}{
		Findings: r.Findings,
		Errors:   r.Errors(),
		Warnings: r.Warnings(),
	}
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
