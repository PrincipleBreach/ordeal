package engine

import (
	"regexp"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator/modifiers"
)

// This file closes two of sigma-go's modifier gaps without forking the engine.
// Both use the library's own extension points:
//
//   - windash is registered into the exported EventValueModifiers map.
//   - null is handled by a small rule rewrite (see rewriteNulls) that feeds
//     sigma-go's existing "null" comparison the value it already knows how to
//     match, instead of the raw YAML nil it rejects.
//
// Measured against SigmaHQ/sigma, windash covers ~108 rules and `Field: null`
// ~85 rules — together the two largest gaps in the pinned engine.

func init() {
	// windash: the Sigma value modifier that lets a rule written with "-flag"
	// also match the alternative dash characters the Windows argument parser
	// accepts (/, en-dash, em-dash, horizontal bar). sigma-go does not ship it.
	// We implement it as an event-value modifier that normalizes those flag
	// prefixes back to "-" in the event before comparison, which yields the same
	// match result as expanding the rule value into every variant.
	modifiers.EventValueModifiers["windash"] = windash{}
}

// dashFlagPrefix matches an alternative dash in flag position: at the start of
// the string or after whitespace. Restricting to flag position avoids rewriting
// slashes inside URLs and paths (http://, C:\ vs C:/), which would otherwise
// manufacture false matches.
var dashFlagPrefix = regexp.MustCompile(`(^|\s)[/\x{2013}\x{2014}\x{2015}]`)

type windash struct{}

func (windash) Modify(value any) (any, error) {
	s := modifiers.CoerceString(value)
	return dashFlagPrefix.ReplaceAllString(s, "$1-"), nil
}

// rewriteNulls converts YAML null match values (`Field: null`) into the string
// "null". sigma-go's default comparator already special-cases a nil event value
// against the expected string "null" (absent field matches), but its value
// coercion rejects a raw nil expected value before the comparator is reached.
// Feeding it "null" bridges that gap. A field present with any other value still
// fails the comparison, so absence semantics are preserved.
func rewriteNulls(rule sigma.Rule) sigma.Rule {
	for name, search := range rule.Detection.Searches {
		for i := range search.EventMatchers {
			for j := range search.EventMatchers[i] {
				vals := search.EventMatchers[i][j].Values
				for k := range vals {
					if vals[k] == nil {
						vals[k] = "null"
					}
				}
			}
		}
		rule.Detection.Searches[name] = search
	}
	return rule
}
