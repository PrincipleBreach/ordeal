package mutate

import (
	"regexp"
	"strings"
)

// --- Windows path mutators -----------------------------------------------
//
// Win32 canonicalizes a path before it ever reaches the filesystem.
// GetFullPathName — and RtlDosPathNameToNtPathName_U beneath it — removes "."
// and ".." segments and collapses runs of separators PURELY LEXICALLY, without
// touching the disk. So C:\Windows\System32\rundll32.exe, its doubled-separator
// form C:\\Windows\System32\rundll32.exe, its dot-segment form
// C:\Windows\System32\.\rundll32.exe and its cancelling-traversal form
// C:\Windows\System32\temp\..\rundll32.exe all name the identical file — the
// intermediate "temp" directory need not exist, because nothing ever looks for
// it. A rule that pins a directory-plus-filename literal misses every one of
// these; a rule that keys on the leaf binary does not.
//
// Two facts bound what these mutators are allowed to touch:
//
//   - The leading \\ of a UNC path is syntax, not a separator run, and the
//     server and share names behind it are resolved by the redirector rather
//     than by lexical canonicalization. Nothing at or before the share is ever
//     rewritten; pathRoot marks the boundary.
//   - A path carrying the \\?\ prefix (or a \\.\ device path) is handed to the
//     object manager verbatim — normalization is SKIPPED — so none of the
//     equivalences above hold. Such values are refused outright.

// pathToken matches a rooted Windows path inside a command line: a drive-letter
// path (C:\Windows\System32\rundll32.exe) or a UNC path (\\server\share\x.exe).
// Whitespace, quotes, commas and shell metacharacters end the match, so an
// unquoted C:\Program Files\x is matched only as far as "C:\Program" — still a
// rooted path, which is all these transforms need.
var pathToken = regexp.MustCompile(`(?i)(?:[A-Z]:|\\\\[A-Za-z0-9._$-]+)\\[^\s"'|&<>,;]*`)

// pathIsSep reports whether b is a Windows path separator.
func pathIsSep(b byte) bool { return b == '\\' || b == '/' }

// pathSkipsNormalization reports whether value contains a prefixed path form for
// which Win32 bypasses normalization, which makes every transform in this file
// unsound.
func pathSkipsNormalization(value string) bool {
	return strings.Contains(value, `\\?\`) || strings.Contains(value, `\\.\`)
}

// pathRoot returns the length of p's root — 3 for "C:\", or the offset past the
// trailing separator of "\\server\share\" for a UNC path — and reports whether p
// is rooted at all. No byte before this offset may be rewritten. A bare
// "\\server" or "\\server\share" has no rewritable interior and is rejected.
func pathRoot(p string) (int, bool) {
	if len(p) >= 3 && p[1] == ':' && p[2] == '\\' {
		return 3, true
	}
	if !strings.HasPrefix(p, `\\`) {
		return 0, false
	}
	rest := p[2:]
	server := strings.IndexByte(rest, '\\')
	if server < 0 {
		return 0, false
	}
	share := strings.IndexByte(rest[server+1:], '\\')
	if share < 0 {
		return 0, false
	}
	return 2 + server + 1 + share + 1, true
}

// pathFind locates the first rooted Windows path in value and returns its
// half-open byte range plus its root length. ok is false when value holds no
// usable path, or when it is a form Win32 does not normalize.
func pathFind(value string) (start, end, root int, ok bool) {
	if pathSkipsNormalization(value) {
		return 0, 0, 0, false
	}
	loc := pathToken.FindStringIndex(value)
	if loc == nil {
		return 0, 0, 0, false
	}
	root, ok = pathRoot(value[loc[0]:loc[1]])
	if !ok {
		return 0, 0, 0, false
	}
	return loc[0], loc[1], root, true
}

// redundantSeparator doubles a separator inside a Windows path. Canonicalization
// collapses any run of separators back to one, so C:\\Windows\System32\cmd.exe
// opens the same file as C:\Windows\System32\cmd.exe. Rules matching a literal
// directory-plus-file string miss the doubled form.
type redundantSeparator struct{}

func (redundantSeparator) Name() string      { return "redundant-separator" }
func (redundantSeparator) Technique() string { return "T1027.010" }
func (redundantSeparator) Describe() string {
	return "Double an interior backslash in a Windows path (C:\\Windows -> C:\\\\Windows)"
}
func (redundantSeparator) Remediation() string {
	return "Collapse separator runs at ingest; prefer |endswith on the leaf binary over a directory-plus-file literal."
}

func (redundantSeparator) Apply(value string) []Result {
	start, end, root, ok := pathFind(value)
	if !ok {
		return nil
	}
	p := value[start:end]
	// The root's own trailing separator is the earliest one that may be doubled:
	// doubling it makes a run that canonicalization collapses, while anything
	// earlier is the UNC \\ marker or the server and share names.
	i := root - 1
	if i < 0 || i >= len(p) || p[i] != '\\' {
		return nil
	}
	if i+1 >= len(p) || pathIsSep(p[i+1]) {
		return nil // nothing follows the root, or the run already exists
	}
	mutated := value[:start] + p[:i] + `\\` + p[i+1:] + value[end:]
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "doubled a path separator; canonicalization collapses the run"}}
}

// pathDotSegment inserts a redundant current-directory segment before the final
// path component. Canonicalization drops \.\ outright, so
// System32\.\rundll32.exe resolves to System32\rundll32.exe.
type pathDotSegment struct{}

func (pathDotSegment) Name() string      { return "path-dot-segment" }
func (pathDotSegment) Technique() string { return "T1027.010" }
func (pathDotSegment) Describe() string {
	return "Insert a redundant \\.\\ before the final path component (System32\\x -> System32\\.\\x)"
}
func (pathDotSegment) Remediation() string {
	return "Resolve \\.\\ and \\..\\ in path tokens at ingest; match the leaf with |endswith and assert the directory via a normalized field."
}

func (pathDotSegment) Apply(value string) []Result {
	start, end, root, ok := pathFind(value)
	if !ok {
		return nil
	}
	p := value[start:end]
	i := strings.LastIndexByte(p, '\\')
	if i < root-1 {
		return nil // the separator belongs to the UNC root; off limits
	}
	if i+1 >= len(p) {
		return nil // trailing separator: there is no final component to shift
	}
	mutated := value[:start] + p[:i+1] + `.\` + p[i+1:] + value[end:]
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "inserted a \\.\\ segment before the final path component"}}
}

// pathTraversalInsertion inserts a directory-then-parent pair that cancels
// lexically. C:\Windows\System32\temp\..\rundll32.exe canonicalizes back to
// C:\Windows\System32\rundll32.exe, and because the removal is lexical the
// "temp" directory never has to exist. UNC paths are skipped: a .. segment there
// is bounded by the share rather than by a drive root, which is not a boundary
// this mutator can reason about from the string alone.
type pathTraversalInsertion struct{}

func (pathTraversalInsertion) Name() string      { return "path-traversal-insertion" }
func (pathTraversalInsertion) Technique() string { return "T1027.010" }
func (pathTraversalInsertion) Describe() string {
	return "Insert a lexically-cancelling \\dir\\..\\ into an absolute path"
}
func (pathTraversalInsertion) Remediation() string {
	return "Collapse \\..\\ at ingest; never anchor a parent-directory-plus-filename pair — match the filename with a leading separator only."
}

func (pathTraversalInsertion) Apply(value string) []Result {
	start, end, root, ok := pathFind(value)
	if !ok {
		return nil
	}
	p := value[start:end]
	if strings.HasPrefix(p, `\\`) {
		return nil // UNC: only drive-letter paths get the traversal filler
	}
	i := strings.LastIndexByte(p, '\\')
	if i < root-1 || i+1 >= len(p) {
		return nil
	}
	mutated := value[:start] + p[:i+1] + `temp\..\` + p[i+1:] + value[end:]
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "inserted a cancelling temp\\..\\ traversal before the final path component"}}
}

// exeExtensionOmission drops the .exe suffix from the command token. CreateProcess
// and the cmd path search append .exe when the command carries no extension, so
// "certutil" starts the same image as "certutil.exe". Only the command token is
// touched: a later argument ending in .exe is a filename the process reads or
// writes, and shortening that would change what the command does.
type exeExtensionOmission struct{}

func (exeExtensionOmission) Name() string      { return "exe-extension-omission" }
func (exeExtensionOmission) Technique() string { return "T1027.010" }
func (exeExtensionOmission) Describe() string {
	return "Drop the .exe suffix from the command token (certutil.exe -> certutil)"
}
func (exeExtensionOmission) Remediation() string {
	return "Match the stem in CommandLine and pin the extension on Image/OriginalFileName, which the kernel resolves canonically."
}

func (exeExtensionOmission) Apply(value string) []Result {
	if pathSkipsNormalization(value) {
		return nil
	}
	head, rest := commandToken(value)
	if len(head) <= len(".exe") || !strings.EqualFold(head[len(head)-4:], ".exe") {
		return nil
	}
	stem := head[:len(head)-4]
	if isOpaque(stem) {
		return nil // payload-shaped token: leave it byte-identical
	}
	return []Result{{Value: stem + rest, Note: "dropped the .exe suffix from the command token"}}
}

func init() {
	register(
		redundantSeparator{},
		pathDotSegment{},
		pathTraversalInsertion{},
		exeExtensionOmission{},
	)
}
