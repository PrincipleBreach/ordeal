package mutate

import (
	"strings"
	"testing"

	"github.com/principlebreach/ordeal/internal/engine"
)

func TestFlagAbbreviation(t *testing.T) {
	got := flagAbbreviation{}.Apply("powershell.exe -NoProfile -EncodedCommand AAAA")
	if len(got) == 0 {
		t.Fatal("expected at least one abbreviation")
	}
	var sawEnc, sawNop bool
	for _, r := range got {
		if strings.Contains(r.Value, "-enc ") {
			sawEnc = true
		}
		if strings.Contains(strings.ToLower(r.Value), "-nop ") {
			sawNop = true
		}
	}
	if !sawEnc {
		t.Errorf("expected -EncodedCommand to abbreviate to -enc, got %+v", got)
	}
	if !sawNop {
		t.Errorf("expected -NoProfile to abbreviate to -nop, got %+v", got)
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

func TestCaseFlipIsReversible(t *testing.T) {
	got := caseFlip{}.Apply("PowerShell")
	if len(got) != 1 || got[0].Value != "pOWERsHELL" {
		t.Fatalf("unexpected case flip: %+v", got)
	}
}

func TestGenerateSkipsNonStringAndEmpty(t *testing.T) {
	base := engine.Event{
		"CommandLine": "powershell.exe -EncodedCommand AAAA",
		"EventID":     4688, // non-string: must be ignored
		"Empty":       "",   // empty: must be ignored
	}
	variants := Generate(base, StringFields(base))
	if len(variants) == 0 {
		t.Fatal("expected variants from CommandLine")
	}
	for _, v := range variants {
		if v.Field != "CommandLine" {
			t.Errorf("mutation touched unexpected field %q", v.Field)
		}
		// Every variant must actually differ from the original.
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
