package engine

import (
	"context"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
)

func compile(t *testing.T, rule string) Matcher {
	t.Helper()
	r, err := sigma.ParseRule([]byte(rule))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, err := NewNative().Compile(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return m
}

func matches(t *testing.T, m Matcher, ev Event) bool {
	t.Helper()
	v, err := m.Match(context.Background(), ev)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	return v.Matched
}

const windashRule = `title: windash
logsource: {category: process_creation}
detection:
  sel:
    CommandLine|windash|contains: '-EncodedCommand'
  condition: sel`

func TestWindashMatchesAlternativeDashes(t *testing.T) {
	m := compile(t, windashRule)
	for _, cmd := range []string{
		"powershell.exe -EncodedCommand AAAA",      // baseline
		"powershell.exe /EncodedCommand AAAA",      // forward slash
		"powershell.exe \u2013EncodedCommand AAAA", // en-dash
		"powershell.exe \u2014EncodedCommand AAAA", // em-dash
	} {
		if !matches(t, m, Event{"CommandLine": cmd}) {
			t.Errorf("windash rule should match %q", cmd)
		}
	}
}

func TestWindashDoesNotOvermatchURLs(t *testing.T) {
	m := compile(t, windashRule)
	// A slash inside a URL must not be normalized into a flag and manufacture a
	// match. This command has no EncodedCommand flag at all.
	if matches(t, m, Event{"CommandLine": "curl.exe http://host/EncodedCommand/path"}) {
		t.Error("windash should not treat a URL path segment as a flag")
	}
}

const nullRule = `title: null-check
logsource: {category: process_creation}
detection:
  sel:
    Image|endswith: '\rundll32.exe'
    CommandLine: null
  condition: sel`

func TestNullMatchesAbsentField(t *testing.T) {
	m := compile(t, nullRule)
	// rundll32 launched with no command line at all — the suspicious case.
	if !matches(t, m, Event{"Image": `C:\Windows\System32\rundll32.exe`}) {
		t.Error("null rule should match when CommandLine is absent")
	}
}

func TestNullDoesNotMatchPresentField(t *testing.T) {
	m := compile(t, nullRule)
	if matches(t, m, Event{
		"Image":       `C:\Windows\System32\rundll32.exe`,
		"CommandLine": "rundll32.exe shell32.dll,Control_RunDLL",
	}) {
		t.Error("null rule should not match when CommandLine is present")
	}
}

func TestOrdinaryRuleStillWorks(t *testing.T) {
	m := compile(t, `title: plain
logsource: {category: process_creation}
detection:
  sel:
    CommandLine|contains: '-urlcache'
  condition: sel`)
	if !matches(t, m, Event{"CommandLine": "certutil.exe -urlcache http://x/y"}) {
		t.Error("ordinary contains rule regressed")
	}
	if matches(t, m, Event{"CommandLine": "certutil.exe -dump"}) {
		t.Error("ordinary rule matched a benign command")
	}
}
