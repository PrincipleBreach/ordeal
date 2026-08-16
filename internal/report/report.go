// Package report renders runner results as human, JSON, or JUnit output.
//
// The human renderer follows the Principle Breach house style: one signal colour
// (red #B70000), hard edges, ALL-CAPS status chips, typographic marks instead of
// emoji. Colour is dropped automatically on a non-TTY so CI logs stay clean.
package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/charmbracelet/lipgloss"
	"github.com/principlebreach/ordeal/internal/runner"
)

// Brand colours (from the Principle Breach design system).
const (
	pbRed   = lipgloss.Color("#B70000")
	pbGreen = lipgloss.Color("#1B7F3A")
	pbWarn  = lipgloss.Color("#C47A00")
	pbGray  = lipgloss.Color("#737373")
)

var (
	stylePass   = lipgloss.NewStyle().Foreground(pbGreen).Bold(true)
	styleFail   = lipgloss.NewStyle().Foreground(pbRed).Bold(true)
	styleWarn   = lipgloss.NewStyle().Foreground(pbWarn).Bold(true)
	styleDim    = lipgloss.NewStyle().Foreground(pbGray)
	styleRule   = lipgloss.NewStyle().Bold(true)
	styleEvaded = lipgloss.NewStyle().Foreground(pbRed)
)

// Format selects an output encoding.
type Format string

const (
	Human Format = "human"
	JSON  Format = "json"
	JUnit Format = "junit"
)

// Tests renders a unit-test report.
func Tests(w io.Writer, r runner.TestReport, format Format) error {
	switch format {
	case JSON:
		return writeJSON(w, r)
	case JUnit:
		return writeJUnit(w, r)
	default:
		return testsHuman(w, r)
	}
}

func testsHuman(w io.Writer, r runner.TestReport) error {
	for _, c := range r.Cases {
		switch {
		case c.Err != nil:
			fmt.Fprintf(w, "%s  %s %s\n", styleFail.Render("ERROR"), c.Name, styleDim.Render("· "+c.Err.Error()))
		case c.Pass:
			fmt.Fprintf(w, "%s   %s\n", stylePass.Render("PASS"), c.Name)
		default:
			detail := fmt.Sprintf("expected match=%v, got match=%v", c.Expected, c.Actual)
			if len(c.MissingSelections) > 0 {
				detail = fmt.Sprintf("selections did not fire: %v", c.MissingSelections)
			}
			fmt.Fprintf(w, "%s   %s %s\n", styleFail.Render("FAIL"), c.Name, styleDim.Render("· "+detail))
		}
	}
	fmt.Fprintln(w)
	summary := fmt.Sprintf("%d passed, %d failed, %d total", r.Passed(), r.Failed(), len(r.Cases))
	if r.OK() {
		fmt.Fprintln(w, stylePass.Render("ALL PASS")+"  "+styleDim.Render(summary))
	} else {
		fmt.Fprintln(w, styleFail.Render("FAILURES")+"  "+styleDim.Render(summary))
	}
	return nil
}

// Mutations renders an adversarial mutation report.
func Mutations(w io.Writer, r runner.MutationReport, format Format) error {
	if format == JSON {
		return writeJSON(w, r)
	}
	return mutationsHuman(w, r)
}

func mutationsHuman(w io.Writer, r runner.MutationReport) error {
	for _, res := range r.Rules {
		if !res.BaselineMatched {
			fmt.Fprintf(w, "%s  %s %s\n", styleWarn.Render("SKIP"), res.CaseName,
				styleDim.Render("· baseline did not fire; fix the rule or fixture first"))
			continue
		}
		if res.Attempted == 0 {
			fmt.Fprintf(w, "%s  %s %s\n", styleWarn.Render("NOTE"), styleRule.Render(res.CaseName),
				styleDim.Render("· no attacker-controlled fields to mutate"))
			continue
		}
		pct := int(res.Score()*100 + 0.5)
		head := fmt.Sprintf("%s  survives %d/%d techniques (%d%%)",
			styleRule.Render(res.CaseName), res.Survived, res.Attempted, pct)
		if len(res.Evaded) == 0 {
			fmt.Fprintf(w, "%s   %s\n", stylePass.Render("HOLD"), head)
			continue
		}
		fmt.Fprintf(w, "%s  %s\n", styleFail.Render("BREACH"), head)
		seenFix := map[string]bool{}
		var fixes []string
		for _, e := range res.Evaded {
			label := "▲ " + e.Mutator
			if e.Variants > 1 {
				label += fmt.Sprintf(" (%d variants)", e.Variants)
			}
			fmt.Fprintf(w, "        %s %s\n",
				styleEvaded.Render(label), styleDim.Render("· "+e.Field+" · "+e.Note))
			fmt.Fprintf(w, "          %s\n", styleDim.Render(e.After))
			if e.Remediation != "" && !seenFix[e.Remediation] {
				seenFix[e.Remediation] = true
				fixes = append(fixes, e.Remediation)
			}
		}
		for _, fix := range fixes {
			fmt.Fprintf(w, "        %s %s\n", styleWarn.Render("fix"), styleDim.Render("· "+fix))
		}
	}
	fmt.Fprintln(w)
	total := r.TotalEvasions()
	summary := fmt.Sprintf("%d detections tested, %d techniques evaded", len(r.Rules), total)
	if r.OK() {
		fmt.Fprintln(w, stylePass.Render("NO EVASIONS")+"  "+styleDim.Render(summary))
	} else {
		fmt.Fprintln(w, styleFail.Render("EVADED")+"  "+styleDim.Render(summary))
	}
	return nil
}

func writeJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// --- JUnit ---------------------------------------------------------------

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Suites   []junitSuite `xml:"testsuite"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
}

type junitSuite struct {
	Name  string      `xml:"name,attr"`
	Cases []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string        `xml:"name,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
	Error   *junitFailure `xml:"error,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
}

func writeJUnit(w io.Writer, r runner.TestReport) error {
	out := junitSuites{Tests: len(r.Cases), Failures: r.Failed()}
	byRule := map[string]*junitSuite{}
	var order []string
	for _, c := range r.Cases {
		s, ok := byRule[c.Suite]
		if !ok {
			s = &junitSuite{Name: c.Suite}
			byRule[c.Suite] = s
			order = append(order, c.Suite)
		}
		jc := junitCase{Name: c.Name}
		switch {
		case c.Err != nil:
			jc.Error = &junitFailure{Message: c.Err.Error()}
		case !c.Pass:
			jc.Failure = &junitFailure{Message: fmt.Sprintf("expected match=%v, got match=%v %v", c.Expected, c.Actual, c.MissingSelections)}
		}
		s.Cases = append(s.Cases, jc)
	}
	for _, k := range order {
		out.Suites = append(out.Suites, *byRule[k])
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
