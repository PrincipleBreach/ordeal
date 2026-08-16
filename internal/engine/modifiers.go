package engine

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator/modifiers"
)

// This file closes sigma-go's modifier gaps without forking the engine. It uses
// the library's own extension points — the exported modifier maps, the rule AST,
// and the placeholder-expander hook — rather than a vendored copy.
//
// Closed here (measured against SigmaHQ/sigma):
//   - windash      (~108 rules) registered event-value modifier
//   - Field: null  (~85 rules)  rule rewrite
//   - base64offset (~5)         rule rewrite (value expansion)
//   - wide / utf16 (~few)       rule rewrite (UTF-16LE encoding)
//   - re sub-flags (~2)         rule rewrite (inline regex flags)
//   - expand       (~32)        no-op modifier + placeholder expander
//
// Not closed: |fieldref (~5 rules) compares two fields of the same event at match
// time, which no exported hook exposes; it needs evaluator internals.

func init() {
	modifiers.EventValueModifiers["windash"] = windash{}
	// expand marks a value as a placeholder to be expanded. sigma-go already
	// expands %name% values when a placeholder expander is configured; the
	// modifier just needs to be known so evaluation does not reject it.
	modifiers.ValueModifiers["expand"] = noopModifier{}
}

// normalizeRule applies every rule-side rewrite before evaluation.
func normalizeRule(rule sigma.Rule) sigma.Rule {
	for name, search := range rule.Detection.Searches {
		for i := range search.EventMatchers {
			for j := range search.EventMatchers[i] {
				rewriteFieldMatcher(&search.EventMatchers[i][j])
			}
		}
		rule.Detection.Searches[name] = search
	}
	return rule
}

// rewriteFieldMatcher expands unsupported value modifiers on one field matcher
// into equivalents the base engine understands, and strips the modifiers it
// consumed. Comparator modifiers (contains, endswith, ...) are preserved in
// place, so a comparator stays in the last position.
func rewriteFieldMatcher(fm *sigma.FieldMatcher) {
	hasWide := hasModifier(fm.Modifiers, "wide") || hasModifier(fm.Modifiers, "utf16le")
	hasB64 := hasModifier(fm.Modifiers, "base64offset")
	reFlags := regexFlags(fm.Modifiers)

	switch {
	case hasB64:
		var expanded []interface{}
		for _, v := range fm.Values {
			s := modifiers.CoerceString(v)
			if hasWide {
				s = wideEncode(s)
			}
			for _, variant := range base64OffsetVariants(s) {
				expanded = append(expanded, variant)
			}
		}
		fm.Values = expanded
	case hasWide:
		for k := range fm.Values {
			fm.Values[k] = wideEncode(modifiers.CoerceString(fm.Values[k]))
		}
	}

	if reFlags != "" {
		prefix := "(?" + reFlags + ")"
		for k := range fm.Values {
			fm.Values[k] = prefix + modifiers.CoerceString(fm.Values[k])
		}
	}

	// Bridge YAML null: sigma-go's default comparator matches an absent event
	// field against the expected string "null", but rejects a raw nil value.
	for k := range fm.Values {
		if fm.Values[k] == nil {
			fm.Values[k] = "null"
		}
	}

	fm.Modifiers = stripConsumed(fm.Modifiers, reFlags != "")
}

func hasModifier(mods []string, name string) bool {
	for _, m := range mods {
		if m == name {
			return true
		}
	}
	return false
}

// regexFlags returns the ordered subset of {i, m, s} present as modifiers when
// the re comparator is used. Sigma writes these as trailing modifiers
// (field|re|i); sigma-go does not know them, so they become inline (?i) flags.
func regexFlags(mods []string) string {
	if !hasModifier(mods, "re") {
		return ""
	}
	var out []byte
	for _, f := range []string{"i", "m", "s"} {
		if hasModifier(mods, f) {
			out = append(out, f[0])
		}
	}
	return string(out)
}

// stripConsumed removes the modifiers rewriteFieldMatcher handled, keeping
// comparators and other modifiers untouched.
func stripConsumed(mods []string, droppedReFlags bool) []string {
	drop := map[string]bool{"wide": true, "utf16le": true, "base64offset": true}
	if droppedReFlags {
		drop["i"], drop["m"], drop["s"] = true, true, true
	}
	var out []string
	for _, m := range mods {
		if drop[m] {
			continue
		}
		out = append(out, m)
	}
	return out
}

// dashFlagPrefix matches an alternative dash in flag position: at the start of
// the string or after whitespace. Restricting to flag position avoids rewriting
// slashes inside URLs and paths, which would otherwise manufacture false matches.
var dashFlagPrefix = regexp.MustCompile(`(^|\s)[/\x{2013}\x{2014}\x{2015}]`)

type windash struct{}

func (windash) Modify(value any) (any, error) {
	return dashFlagPrefix.ReplaceAllString(modifiers.CoerceString(value), "$1-"), nil
}

type noopModifier struct{}

func (noopModifier) Modify(value any) (any, error) { return value, nil }

// wideEncode returns the UTF-16LE byte string of s (each byte followed by a null
// byte for ASCII input), matching Sigma's |wide modifier.
func wideEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		b.WriteByte(c)
		b.WriteByte(0)
	}
	return b.String()
}

// base64OffsetVariants returns the three base64 encodings of s at byte offsets 0,
// 1, and 2, trimmed at the boundaries so each is a substring that appears when s
// is embedded in a larger base64 blob. This mirrors the Sigma |base64offset
// modifier (and pySigma's implementation).
func base64OffsetVariants(s string) []string {
	starts := []int{0, 2, 3}
	trimEnd := []int{0, 3, 2}
	var out []string
	for i := 0; i < 3; i++ {
		padded := append([]byte(strings.Repeat(" ", i)), []byte(s)...)
		enc := base64.StdEncoding.EncodeToString(padded)
		start := starts[i]
		end := len(enc) - trimEnd[i]
		if start >= end {
			continue
		}
		out = append(out, enc[start:end])
	}
	return out
}

// placeholderExpander turns a placeholders map into the expander sigma-go calls
// for %name% values (used by the |expand modifier and bare placeholders).
func placeholderExpander(m map[string][]string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, name string) ([]string, error) {
		key := strings.Trim(name, "%")
		vals, ok := m[key]
		if !ok {
			return nil, fmt.Errorf("no definition for placeholder %s", name)
		}
		return vals, nil
	}
}
