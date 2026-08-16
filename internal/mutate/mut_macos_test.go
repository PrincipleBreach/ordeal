package mutate

import "testing"

// macCase is one mutator applied to one command line. want is the single
// expected mutated value, or "" when the mutator must decline the input.
type macCase struct {
	name    string
	mutator Mutator
	in      string
	want    string
}

func TestMacMutators(t *testing.T) {
	cases := []macCase{
		// --- macos-private-path-prefix ---
		{
			name:    "private/tmp rewritten",
			mutator: macPrivatePathPrefix{},
			in:      `cp /Users/admin/Library/agent /tmp/.updater`,
			want:    `cp /Users/admin/Library/agent /private/tmp/.updater`,
		},
		{
			name:    "private/etc rewritten",
			mutator: macPrivatePathPrefix{},
			in:      `grep -i root /etc/sudoers`,
			want:    `grep -i root /private/etc/sudoers`,
		},
		{
			name:    "private/var rewritten",
			mutator: macPrivatePathPrefix{},
			in:      `ls -la /var/root/.ssh`,
			want:    `ls -la /private/var/root/.ssh`,
		},
		{
			name:    "only the first occurrence is rewritten",
			mutator: macPrivatePathPrefix{},
			in:      `cp /tmp/a /tmp/b`,
			want:    `cp /private/tmp/a /tmp/b`,
		},
		{
			name:    "bare /tmp at end of line is a whole segment",
			mutator: macPrivatePathPrefix{},
			in:      `cd /tmp`,
			want:    `cd /private/tmp`,
		},
		{
			name:    "an already-private path is not rewritten twice",
			mutator: macPrivatePathPrefix{},
			in:      `cat /private/tmp/.updater`,
		},
		{
			name:    "/tmpfoo is not a /tmp path segment",
			mutator: macPrivatePathPrefix{},
			in:      `ls /tmpfoo/bar`,
		},
		{
			name:    "no symlinked prefix present",
			mutator: macPrivatePathPrefix{},
			in:      `ls -la /Users/admin/Library/LaunchAgents`,
		},

		// --- osascript-lang-explicit ---
		{
			name:    "default component named explicitly",
			mutator: macOsascriptLang{},
			in:      `osascript -e 'do shell script "whoami"'`,
			want:    `osascript -l AppleScript -e 'do shell script "whoami"'`,
		},
		{
			name:    "absolute interpreter path is recognized",
			mutator: macOsascriptLang{},
			in:      `/usr/bin/osascript -e 'display dialog "hi"'`,
			want:    `/usr/bin/osascript -l AppleScript -e 'display dialog "hi"'`,
		},
		{
			name:    "an invocation already naming -l is left alone",
			mutator: macOsascriptLang{},
			in:      `osascript -l JavaScript -e 'ObjC.import("Cocoa")'`,
		},
		{
			name:    "a script-file invocation has no -e to separate",
			mutator: macOsascriptLang{},
			in:      `osascript /tmp/stage2.scpt`,
		},
		{
			name:    "another interpreter is not osascript",
			mutator: macOsascriptLang{},
			in:      `python3 -e 'x'`,
		},

		// --- base64-flagcase ---
		{
			name:    "decode flag swapped for -D",
			mutator: macBase64FlagCase{},
			in:      `base64 -d /tmp/payload.b64`,
			want:    `base64 -D /tmp/payload.b64`,
		},
		{
			name:    "the long --decode form is left alone",
			mutator: macBase64FlagCase{},
			in:      `base64 --decode /tmp/payload.b64`,
		},
		{
			name:    "encoding has no decode flag",
			mutator: macBase64FlagCase{},
			in:      `base64 -i /tmp/payload -o /tmp/payload.b64`,
		},
		{
			name:    "base64 as a subcommand is not the command token",
			mutator: macBase64FlagCase{},
			in:      `openssl base64 -d -in payload.b64`,
		},

		// --- python-c-spacing ---
		{
			name:    "-c argument attached to the flag",
			mutator: macPythonCSpacing{},
			in:      `python3 -c 'import socket,os,pty;s=socket.socket()'`,
			want:    `python3 -c'import socket,os,pty;s=socket.socket()'`,
		},
		{
			name:    "python2 with a double-quoted program",
			mutator: macPythonCSpacing{},
			in:      `/usr/bin/python2 -c "import pty; pty.spawn('/bin/zsh')"`,
			want:    `/usr/bin/python2 -c"import pty; pty.spawn('/bin/zsh')"`,
		},
		{
			name:    "a script-file invocation has no -c",
			mutator: macPythonCSpacing{},
			in:      `python3 /tmp/stage2.py --quiet`,
		},
		{
			name:    "-c belonging to another interpreter is not python's",
			mutator: macPythonCSpacing{},
			in:      `perl -c 'print 1'`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.mutator.Apply(tc.in)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("%s should have declined %q, got %+v", tc.mutator.Name(), tc.in, got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("%s: expected 1 variant for %q, got %d (%+v)", tc.mutator.Name(), tc.in, len(got), got)
			}
			if got[0].Value != tc.want {
				t.Errorf("%s:\n in   %q\n got  %q\n want %q", tc.mutator.Name(), tc.in, got[0].Value, tc.want)
			}
			if got[0].Value == tc.in {
				t.Errorf("%s returned a no-op variant for %q", tc.mutator.Name(), tc.in)
			}
			if got[0].Note == "" {
				t.Errorf("%s returned a variant with no note", tc.mutator.Name())
			}
		})
	}
}

// macMutators is the set registered by this file.
func macMutators() []Mutator {
	return []Mutator{
		macPrivatePathPrefix{}, macOsascriptLang{},
		macBase64FlagCase{}, macPythonCSpacing{},
	}
}

func TestMacMutatorsAreDeterministic(t *testing.T) {
	inputs := []string{
		`cp agent /tmp/.updater`,
		`osascript -e 'do shell script "whoami"'`,
		`base64 -d /tmp/payload.b64`,
		`python3 -c 'import os'`,
		`ls -la /Users/admin`,
	}
	for _, m := range macMutators() {
		for _, in := range inputs {
			first := m.Apply(in)
			for i := 0; i < 5; i++ {
				again := m.Apply(in)
				if len(again) != len(first) {
					t.Fatalf("%s: variant count varies for %q", m.Name(), in)
				}
				for j := range again {
					if again[j] != first[j] {
						t.Fatalf("%s: output varies for %q: %+v vs %+v", m.Name(), in, first, again)
					}
				}
			}
		}
	}
}

func TestMacBase64FlagCaseIsNotLinuxSafe(t *testing.T) {
	// GNU coreutils base64 accepts -d and --decode but not -D, so tagging this
	// mutator for Linux would emit a variant that fails to run there.
	for _, p := range platformsOf(macBase64FlagCase{}) {
		if p == Linux || p == AnyOS {
			t.Errorf("base64-flagcase must not claim %q: GNU base64 has no -D", p)
		}
	}
	if len(ForPlatform([]Mutator{macBase64FlagCase{}}, MacOS)) != 1 {
		t.Error("base64-flagcase should apply to macos")
	}
}

func TestMacMutatorsRegistered(t *testing.T) {
	want := map[string]bool{
		"macos-private-path-prefix": true,
		"osascript-lang-explicit":   true,
		"base64-flagcase":           true,
		"python-c-spacing":          true,
	}
	for _, m := range Catalog() {
		delete(want, m.Name())
	}
	for name := range want {
		t.Errorf("mutator %q is not in the catalog", name)
	}
}
