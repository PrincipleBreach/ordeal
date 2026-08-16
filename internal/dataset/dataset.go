// Package dataset loads real telemetry into Ordeal's event model.
//
// Ordeal's own suites carry hand-written events, but the rules under test are
// ultimately judged against production logs. This package reads the shapes those
// logs actually arrive in — JSON arrays, newline-delimited JSON, SigmaHQ's
// EVTX-rendered regression corpus, winlogbeat exports — and flattens them into
// the one shape the engine understands: a flat map keyed by Sigma taxonomy field
// names. Everything downstream (matching, mutation, reporting) then gets to
// ignore where an event came from.
//
// Flattening deliberately stops short of renaming fields. Mapping a source's
// field names onto a rule's expected taxonomy is what sigma-go configs are for;
// doing it here as well would give a rule two places to be silently mis-mapped.
package dataset

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/principlebreach/ordeal/internal/engine"
)

// maxLineBytes caps a single NDJSON record. bufio.Scanner defaults to 64 KiB,
// which real telemetry blows past routinely: one base64 -EncodedCommand or a
// rendered EVTX record with an embedded script block is comfortably larger.
const maxLineBytes = 16 << 20

// utf8BOM prefixes files written by Windows tooling (Out-File, Export-Csv).
// Left in place it fails the decode with an "invalid character" error pointing
// at offset 0, which is a maddening way to learn your file is fine.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Load reads a telemetry file and returns its records, each passed through
// [Normalize]. The format is chosen by extension:
//
//	.json            a JSON array of objects, a single object, or an object
//	                 wrapping the records under "records"/"Records"
//	.jsonl, .ndjson  one JSON object per line; blank lines are skipped
//
// Errors carry the file path and, for line-oriented formats, the line number:
// a corpus of ten thousand records is only debuggable if the loader says which
// one broke.
func Load(path string) ([]engine.Event, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dataset: %w", err)
	}
	data = bytes.TrimPrefix(data, utf8BOM)

	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".json":
		return loadJSON(path, data)
	case ".jsonl", ".ndjson":
		return loadLines(path, data)
	case "":
		return nil, fmt.Errorf("dataset: %s: no file extension; want .json, .jsonl, or .ndjson", path)
	default:
		return nil, fmt.Errorf("dataset: %s: unsupported extension %q; want .json, .jsonl, or .ndjson", path, ext)
	}
}

// loadJSON decodes a whole-file JSON document. The leading token picks the
// layout rather than trial-and-error unmarshalling, so a malformed array
// reports as a malformed array instead of "cannot unmarshal into object".
func loadJSON(path string, data []byte) ([]engine.Event, error) {
	doc := bytes.TrimSpace(data)
	if len(doc) == 0 {
		return nil, fmt.Errorf("dataset: %s: file is empty", path)
	}

	switch doc[0] {
	case '[':
		var raw []map[string]interface{}
		if err := json.Unmarshal(doc, &raw); err != nil {
			return nil, fmt.Errorf("dataset: %s: decoding JSON array: %w", path, err)
		}
		events := make([]engine.Event, 0, len(raw))
		for i, rec := range raw {
			if rec == nil {
				return nil, fmt.Errorf("dataset: %s: element %d is null, want an object", path, i)
			}
			events = append(events, Normalize(rec))
		}
		return events, nil

	case '{':
		var raw map[string]interface{}
		if err := json.Unmarshal(doc, &raw); err != nil {
			return nil, fmt.Errorf("dataset: %s: decoding JSON object: %w", path, err)
		}
		if records, key, ok := recordsArray(raw); ok {
			events := make([]engine.Event, 0, len(records))
			for i, rec := range records {
				obj, ok := asObject(rec)
				if !ok {
					return nil, fmt.Errorf("dataset: %s: %s[%d] is %T, want an object", path, key, i, rec)
				}
				events = append(events, Normalize(obj))
			}
			return events, nil
		}
		return []engine.Event{Normalize(raw)}, nil

	default:
		return nil, fmt.Errorf("dataset: %s: want a JSON object or array, found %q", path, string(doc[0]))
	}
}

// loadLines decodes newline-delimited JSON. Blank lines are tolerated because
// exporters and shell redirection produce them; anything else that fails to
// decode is an error, since silently dropping a record would understate a
// rule's coverage.
func loadLines(path string, data []byte) ([]engine.Event, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	var events []engine.Event
	line := 0
	for sc.Scan() {
		line++
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(text, &raw); err != nil {
			return nil, fmt.Errorf("dataset: %s:%d: %w", path, line, err)
		}
		if raw == nil {
			return nil, fmt.Errorf("dataset: %s:%d: record is null, want an object", path, line)
		}
		events = append(events, Normalize(raw))
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("dataset: %s:%d: record exceeds the %d byte line limit", path, line+1, maxLineBytes)
		}
		return nil, fmt.Errorf("dataset: %s:%d: %w", path, line+1, err)
	}
	return events, nil
}

// recordsKeys are the wrapper keys used by tools that emit one JSON document
// per query rather than per event (Get-WinEvent | ConvertTo-Json, Azure/AWS log
// exports). It returns the matched key so errors can name it.
var recordsKeys = []string{"records", "Records"}

func recordsArray(raw map[string]interface{}) ([]interface{}, string, bool) {
	for _, key := range recordsKeys {
		if arr, ok := asArray(raw[key]); ok {
			return arr, key, true
		}
	}
	return nil, "", false
}

// Normalize flattens a decoded record into a Sigma-shaped event.
//
// It recognizes the two nesting conventions that dominate Windows telemetry:
//
//   - Event.System.<X> and Event.EventData.<X>, the EVTX-rendered shape used by
//     SigmaHQ's regression corpus. EventData may be a map, an array of
//     {"Name","#text"} pairs, or a map whose "Data" key holds that array,
//     depending on which XML-to-JSON converter produced it.
//   - winlog.<X> and winlog.event_data.<X>, the winlogbeat/ECS shape.
//
// Already-flat records pass through unchanged, and so does anything whose
// nesting is unrecognized: an unusual export is degraded input, not a fatal
// error, and a rule that needs the missing field will fail loudly on its own.
// Where a nested field collides with a top-level one the nested value wins — it
// is the record's own payload, whereas the top-level copy is the exporter's.
//
// Value types are preserved as decoded (string, float64, bool), so numeric
// comparisons downstream keep working.
func Normalize(raw map[string]interface{}) engine.Event {
	out := make(engine.Event, len(raw))
	for k, v := range raw {
		out[k] = v
	}

	if ev, ok := asObject(raw["Event"]); ok {
		if expandWindowsEvent(out, ev) {
			delete(out, "Event")
		}
	}
	if wl, ok := asObject(raw["winlog"]); ok {
		expandWinlog(out, wl)
		delete(out, "winlog")
	}
	return out
}

// eventSections are the Event children worth hoisting, ordered least to most
// specific: when System and EventData both carry a field, the payload wins.
var eventSections = []string{"System", "UserData", "EventData"}

// expandWindowsEvent hoists the known Event children and reports whether any
// were recognized. A false result leaves the Event key intact, since dropping
// a container we failed to understand would lose the data outright.
func expandWindowsEvent(out engine.Event, ev map[string]interface{}) bool {
	hoisted := false
	for _, section := range eventSections {
		v, ok := ev[section]
		if !ok {
			continue
		}
		if mergeSection(out, v) {
			hoisted = true
		}
	}
	return hoisted
}

// winlogNested are winlog children holding field sets rather than scalars,
// hoisted after the sibling metadata so the payload wins any collision.
var winlogNested = []string{"user_data", "event_data"}

func expandWinlog(out engine.Event, wl map[string]interface{}) {
	for k, v := range wl {
		if slices.Contains(winlogNested, k) {
			continue
		}
		out[k] = v
	}
	for _, k := range winlogNested {
		v, ok := wl[k]
		if !ok {
			continue
		}
		if !mergeSection(out, v) {
			out[k] = v // unrecognized shape: keep it rather than drop it
		}
	}
}

// mergeSection copies one field-set section onto the event, in whichever of the
// three encodings the producer chose. It reports whether the section was
// understood.
func mergeSection(out engine.Event, section interface{}) bool {
	switch s := section.(type) {
	case map[string]interface{}:
		for k, v := range s {
			// EVTX converters keep the real fields one level deeper, under a
			// "Data" array of Name/#text pairs.
			if k == "Data" && mergePairs(out, v) {
				continue
			}
			out[k] = collapseText(v)
		}
		return true
	case []interface{}:
		return mergePairs(out, s)
	}
	return false
}

// mergePairs flattens the array-of-pairs encoding produced by XML-to-JSON
// converters: [{"Name":"Image","#text":"C:\\x.exe"}, ...]. It reports whether
// at least one named pair was found, so callers can fall back for arrays that
// are not pairs at all (unnamed <Data> elements, for instance).
func mergePairs(out engine.Event, v interface{}) bool {
	switch pairs := v.(type) {
	case []interface{}:
		merged := false
		for _, p := range pairs {
			obj, ok := asObject(p)
			if !ok {
				continue
			}
			if mergePair(out, obj) {
				merged = true
			}
		}
		return merged
	case map[string]interface{}:
		return mergePair(out, pairs)
	}
	return false
}

func mergePair(out engine.Event, pair map[string]interface{}) bool {
	name, ok := pairName(pair)
	if !ok {
		return false
	}
	out[name] = pairValue(pair)
	return true
}

// pairNameKeys covers converters that prefix XML attributes ("@Name") and those
// that do not ("Name").
var pairNameKeys = []string{"Name", "@Name", "name", "@name"}

func pairName(pair map[string]interface{}) (string, bool) {
	for _, k := range pairNameKeys {
		if s, ok := pair[k].(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

// pairTextKeys covers the same split for element text content.
var pairTextKeys = []string{"#text", "#content", "Value", "value"}

// pairValue returns a pair's text content, or the empty string for a named
// element that carried none. Present-but-empty differs from absent in a way
// Sigma cares about: rules do test for empty values.
func pairValue(pair map[string]interface{}) interface{} {
	for _, k := range pairTextKeys {
		if v, ok := pair[k]; ok {
			return v
		}
	}
	return ""
}

// collapseText unwraps an element rendered as attributes plus text — EventID
// arriving as {"@Qualifiers":"","#text":"4688"} is routine — down to the text.
// The attributes are XML bookkeeping; the text is the value rules match on.
func collapseText(v interface{}) interface{} {
	obj, ok := asObject(v)
	if !ok {
		return v
	}
	for _, k := range pairTextKeys {
		if text, ok := obj[k]; ok {
			return text
		}
	}
	return v
}

func asObject(v interface{}) (map[string]interface{}, bool) {
	obj, ok := v.(map[string]interface{})
	return obj, ok && obj != nil
}

func asArray(v interface{}) ([]interface{}, bool) {
	arr, ok := v.([]interface{})
	return arr, ok
}
