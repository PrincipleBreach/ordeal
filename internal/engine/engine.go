// Package engine evaluates Sigma rules against individual events.
//
// The engine is deliberately hidden behind a small interface. Ordeal's value is
// not the evaluator — it is what we do around it (adversarial mutation). Keeping
// the matcher behind an interface means the underlying implementation can be
// swapped (a vendored sigma-go fork, an rsigma subprocess) without touching the
// mutation, runner, or reporting layers.
package engine

import (
	"context"
	"fmt"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
)

// Event is a single normalized log record, keyed by Sigma taxonomy field names
// (for example "Image", "CommandLine"). Values are typically strings but may be
// numbers or booleans.
type Event = map[string]interface{}

// Verdict is the result of matching one event against one rule. It carries the
// per-selection breakdown, not just a boolean: a mutation that keeps a rule
// firing overall while flipping which selection fired is still a regression, and
// only the breakdown can see it.
type Verdict struct {
	Matched    bool
	Selections map[string]bool
}

// Matcher evaluates events against a single compiled rule.
type Matcher interface {
	// Match reports whether event trips the rule.
	Match(ctx context.Context, event Event) (Verdict, error)
	// Title is the rule title, for diagnostics.
	Title() string
}

// Engine compiles Sigma rules into Matchers.
type Engine interface {
	Name() string
	Compile(rule sigma.Rule, configs ...sigma.Config) (Matcher, error)
}

// Native is the built-in engine, backed by bradleyjkemp/sigma-go.
type Native struct{}

// NewNative returns the default in-process Sigma engine.
func NewNative() Native { return Native{} }

// Name identifies the engine in output and error messages.
func (Native) Name() string { return "native/sigma-go" }

// Compile prepares a rule for repeated evaluation.
func (Native) Compile(rule sigma.Rule, configs ...sigma.Config) (Matcher, error) {
	if rule.Title == "" && rule.ID == "" {
		return nil, fmt.Errorf("engine: rule is missing both title and id")
	}
	opts := make([]evaluator.Option, 0, 1)
	if len(configs) > 0 {
		opts = append(opts, evaluator.WithConfig(configs...))
	}
	// Close the `Field: null` gap before evaluation (see rewriteNulls). windash
	// is handled by the modifier registered in this package's init.
	rule = rewriteNulls(rule)
	return &nativeMatcher{
		title: rule.Title,
		eval:  evaluator.ForRule(rule, opts...),
	}, nil
}

type nativeMatcher struct {
	title string
	eval  *evaluator.RuleEvaluator
}

func (m *nativeMatcher) Title() string { return m.title }

func (m *nativeMatcher) Match(ctx context.Context, event Event) (Verdict, error) {
	res, err := m.eval.Matches(ctx, event)
	if err != nil {
		return Verdict{}, fmt.Errorf("engine: evaluating %q: %w", m.title, err)
	}
	return Verdict{Matched: res.Match, Selections: res.SearchResults}, nil
}
