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

func TestBase64OffsetVariantsVector(t *testing.T) {
	// Canonical Sigma test vector for "cmd".
	got := base64OffsetVariants("cmd")
	want := []string{"Y21k", "NtZ", "jbW"}
	if len(got) != 3 {
		t.Fatalf("expected 3 variants, got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("variant %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBase64OffsetMatches(t *testing.T) {
	m := compile(t, `title: b64
logsource: {category: process_creation}
detection:
  sel:
    CommandLine|base64offset|contains: 'cmd'
  condition: sel`)
	// A base64 blob embedding the offset-0 encoding of "cmd".
	if !matches(t, m, Event{"CommandLine": "powershell -enc AAAAY21kAAAA"}) {
		t.Error("base64offset rule should match an embedded encoding")
	}
	if matches(t, m, Event{"CommandLine": "powershell -enc ZZZZZZZZ"}) {
		t.Error("base64offset rule matched a blob with no encoding")
	}
}

func TestWideMatches(t *testing.T) {
	m := compile(t, `title: wide
logsource: {category: process_creation}
detection:
  sel:
    CommandLine|wide|contains: 'cmd'
  condition: sel`)
	wide := "c\x00m\x00d\x00"
	if !matches(t, m, Event{"CommandLine": "prefix " + wide + " suffix"}) {
		t.Error("wide rule should match a UTF-16LE encoded substring")
	}
	if matches(t, m, Event{"CommandLine": "plain cmd here"}) {
		t.Error("wide rule should not match plain ASCII cmd")
	}
}

func TestReSubFlagCaseInsensitive(t *testing.T) {
	m := compile(t, `title: re
logsource: {category: process_creation}
detection:
  sel:
    CommandLine|re|i: 'POWERSHELL'
  condition: sel`)
	if !matches(t, m, Event{"CommandLine": "start powershell.exe -nop"}) {
		t.Error("re|i rule should match case-insensitively")
	}
}

func TestExpandPlaceholder(t *testing.T) {
	r, err := sigma.ParseRule([]byte(`title: expand
logsource: {category: process_creation}
detection:
  sel:
    CommandLine|expand|contains: '%tool%'
  condition: sel`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewNative().Compile(r, WithPlaceholders(map[string][]string{"tool": {"mimikatz", "rubeus"}}))
	if err != nil {
		t.Fatal(err)
	}
	if !matches(t, m, Event{"CommandLine": "run mimikatz.exe now"}) {
		t.Error("expand rule should match a defined placeholder value")
	}
	if matches(t, m, Event{"CommandLine": "run notepad.exe"}) {
		t.Error("expand rule should not match an undefined value")
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
