package dataset

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/principlebreach/ordeal/internal/engine"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name string
		file string
		want []engine.Event
	}{
		{
			name: "jsonl passes flat records through and skips blank lines",
			file: "flat.jsonl",
			want: []engine.Event{
				{
					"Image":       `C:\Windows\System32\cmd.exe`,
					"CommandLine": "cmd.exe /c whoami",
					"EventID":     float64(1),
				},
				{
					"Image":       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
					"CommandLine": "powershell.exe -NoProfile -EncodedCommand AAAA",
					"EventID":     float64(1),
					"Elevated":    true,
				},
			},
		},
		{
			name: "json array of EVTX-rendered records",
			file: "evtx_nested.json",
			want: []engine.Event{
				{
					"Provider": map[string]interface{}{
						"@Name": "Microsoft-Windows-Sysmon",
						"@Guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
					},
					"EventID":     "1",
					"Channel":     "Microsoft-Windows-Sysmon/Operational",
					"Computer":    "WORKSTATION-01",
					"Image":       `C:\Windows\System32\rundll32.exe`,
					"CommandLine": "rundll32.exe shell32.dll,Control_RunDLL",
					"ParentImage": `C:\Windows\explorer.exe`,
				},
			},
		},
		{
			name: "single json object with EventData as Name/#text pairs",
			file: "evtx_pairs.json",
			want: []engine.Event{
				{
					"EventID":         float64(4688),
					"Channel":         "Security",
					"NewProcessName":  `C:\Windows\System32\net.exe`,
					"CommandLine":     "net user attacker P@ssw0rd /add",
					"SubjectUserName": "",
				},
			},
		},
		{
			name: "records wrapper around winlogbeat documents",
			file: "winlog.json",
			want: []engine.Event{
				{
					"@timestamp":  "2024-05-01T12:00:00.000Z",
					"message":     "Process Create",
					"channel":     "Microsoft-Windows-Sysmon/Operational",
					"event_id":    float64(1),
					"Image":       `C:\Users\dev\AppData\Local\Temp\payload.exe`,
					"ParentImage": `C:\Windows\explorer.exe`,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatalf("Load(%s): %v", tt.file, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Load(%s) =\n%#v\nwant\n%#v", tt.file, got, tt.want)
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string // substrings the error must carry
	}{
		{
			name: "malformed jsonl names the offending line",
			path: filepath.Join("testdata", "malformed.jsonl"),
			want: []string{"malformed.jsonl:3", "unexpected end"},
		},
		{
			name: "missing file",
			path: filepath.Join("testdata", "absent.jsonl"),
			want: []string{"dataset:", "absent.jsonl"},
		},
		{
			name: "unsupported extension",
			path: filepath.Join("testdata", "flat.jsonl"), // path exists; extension is swapped below
			want: []string{"unsupported extension"},
		},
	}

	// The unsupported-extension case needs a real file with a wrong suffix.
	evtx := filepath.Join(t.TempDir(), "corpus.evtx")
	writeFile(t, evtx, "{}")
	tests[2].path = evtx

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.path)
			if err == nil {
				t.Fatalf("Load(%s): want error, got nil", tt.path)
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestLoadRejectsMalformedDocuments(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		file    string
		content string
		want    string
	}{
		{"empty json", "empty.json", "  \n", "file is empty"},
		{"scalar json", "scalar.json", `"just a string"`, "want a JSON object or array"},
		{"truncated array", "broken.json", `[{"Image":"a"}`, "decoding JSON array"},
		{"null element", "nulls.json", `[null]`, "element 0 is null"},
		{"non-object record", "records.json", `{"records":[1]}`, "records[0] is float64"},
		{"null jsonl record", "null.jsonl", "null\n", "null.jsonl:1"},
		{"no extension", "corpus", `{}`, "no file extension"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.file)
			writeFile(t, path, tt.content)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load(%s): want error, got nil", tt.file)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestLoadEmptyJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.jsonl")
	writeFile(t, path, "\n\n   \n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no events from a blank file, got %d", len(got))
	}
}

// TestLoadStripsBOM guards the Windows path: PowerShell redirection writes a
// UTF-8 BOM that otherwise fails the decode at offset 0.
func TestLoadStripsBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bom.json")
	writeFile(t, path, "\xef\xbb\xbf{\"Image\":\"cmd.exe\"}")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0]["Image"] != "cmd.exe" {
		t.Errorf("unexpected events: %#v", got)
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		want engine.Event
	}{
		{
			name: "flat record is unchanged",
			raw: map[string]interface{}{
				"Image":       "cmd.exe",
				"EventID":     float64(1),
				"Elevated":    true,
				"CommandLine": "",
			},
			want: engine.Event{
				"Image":       "cmd.exe",
				"EventID":     float64(1),
				"Elevated":    true,
				"CommandLine": "",
			},
		},
		{
			name: "Event.EventData map form",
			raw: map[string]interface{}{
				"Event": map[string]interface{}{
					"System":    map[string]interface{}{"Channel": "Security"},
					"EventData": map[string]interface{}{"Image": "net.exe"},
				},
			},
			want: engine.Event{"Channel": "Security", "Image": "net.exe"},
		},
		{
			name: "EventData as a bare array of pairs",
			raw: map[string]interface{}{
				"Event": map[string]interface{}{
					"EventData": []interface{}{
						map[string]interface{}{"Name": "Image", "#text": "net.exe"},
						map[string]interface{}{"@Name": "User", "#text": "SYSTEM"},
					},
				},
			},
			want: engine.Event{"Image": "net.exe", "User": "SYSTEM"},
		},
		{
			name: "UserData is hoisted alongside System",
			raw: map[string]interface{}{
				"Event": map[string]interface{}{
					"System":   map[string]interface{}{"EventID": float64(4104)},
					"UserData": map[string]interface{}{"ScriptBlockText": "IEX(...)"},
				},
			},
			want: engine.Event{"EventID": float64(4104), "ScriptBlockText": "IEX(...)"},
		},
		{
			name: "EventData outranks System on collision",
			raw: map[string]interface{}{
				"Event": map[string]interface{}{
					"System":    map[string]interface{}{"Image": "from-system"},
					"EventData": map[string]interface{}{"Image": "from-eventdata"},
				},
			},
			want: engine.Event{"Image": "from-eventdata"},
		},
		{
			name: "attribute-wrapped text collapses to its value",
			raw: map[string]interface{}{
				"Event": map[string]interface{}{
					"System": map[string]interface{}{
						"EventID":  map[string]interface{}{"#text": "4688", "@Qualifiers": ""},
						"Provider": map[string]interface{}{"@Name": "Microsoft-Windows-Security-Auditing"},
					},
				},
			},
			want: engine.Event{
				"EventID":  "4688",
				"Provider": map[string]interface{}{"@Name": "Microsoft-Windows-Security-Auditing"},
			},
		},
		{
			name: "winlog form hoists metadata and event_data",
			raw: map[string]interface{}{
				"message": "Process Create",
				"winlog": map[string]interface{}{
					"channel":    "Security",
					"event_id":   float64(4688),
					"event_data": map[string]interface{}{"NewProcessName": "net.exe"},
				},
			},
			want: engine.Event{
				"message":        "Process Create",
				"channel":        "Security",
				"event_id":       float64(4688),
				"NewProcessName": "net.exe",
			},
		},
		{
			name: "unrecognized Event nesting passes through untouched",
			raw: map[string]interface{}{
				"Event": map[string]interface{}{"Unknown": map[string]interface{}{"a": "b"}},
			},
			want: engine.Event{
				"Event": map[string]interface{}{"Unknown": map[string]interface{}{"a": "b"}},
			},
		},
		{
			name: "Event as a scalar is left alone",
			raw:  map[string]interface{}{"Event": "not an object", "Image": "cmd.exe"},
			want: engine.Event{"Event": "not an object", "Image": "cmd.exe"},
		},
		{
			name: "winlog.event_data of an unexpected type is kept",
			raw: map[string]interface{}{
				"winlog": map[string]interface{}{"channel": "Security", "event_data": "opaque"},
			},
			want: engine.Event{"channel": "Security", "event_data": "opaque"},
		},
		{
			name: "unnamed Data elements are kept as-is",
			raw: map[string]interface{}{
				"Event": map[string]interface{}{
					"EventData": map[string]interface{}{"Data": []interface{}{"first", "second"}},
				},
			},
			want: engine.Event{"Data": []interface{}{"first", "second"}},
		},
		{
			name: "empty record yields an empty event",
			raw:  map[string]interface{}{},
			want: engine.Event{},
		},
		{
			name: "nil record yields an empty event",
			raw:  nil,
			want: engine.Event{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Normalize(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Normalize() =\n%#v\nwant\n%#v", got, tt.want)
			}
		})
	}
}

// TestNormalizeDoesNotMutateInput matters because callers replay the same
// decoded corpus through several rules; a normalizer that edited its input
// would leak the first rule's view into the second.
func TestNormalizeDoesNotMutateInput(t *testing.T) {
	raw := map[string]interface{}{
		"Event": map[string]interface{}{
			"EventData": map[string]interface{}{"Image": "net.exe"},
		},
	}
	Normalize(raw)
	if _, ok := raw["Event"]; !ok {
		t.Error("Normalize removed the Event key from its input")
	}
	if _, ok := raw["Image"]; ok {
		t.Error("Normalize wrote a hoisted field back into its input")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
