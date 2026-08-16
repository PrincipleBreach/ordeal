package mutate

// Network-indicator mutators. Every one of these rewrites the *surface form* of an
// http(s) URL in a command line while leaving the request the host actually makes
// unchanged. They exist because a very large share of real Sigma rules pin a
// download to a literal URL, a dotted-quad IP, or a filename glued to a path — all
// of which an operator can restyle for free before ever touching their tooling.
//
// A mutator that cannot prove equivalence declines (returns nil) rather than
// guessing: a false evasion sends a detection engineer chasing a hole that is not
// there, which is worse than missing a real one.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	register(
		ipDecimal{},
		ipHex{},
		urlDefaultPort{},
		urlPercentEncode{},
		urlPathTraversal{},
	)
}

// --- URL location and splitting -----------------------------------------

// netURLPattern locates http(s) URL tokens in a command line. The character class
// stops at whitespace, quotes and shell metacharacters, which is where a URL
// argument ends in practice.
var netURLPattern = regexp.MustCompile(`(?i)https?://[^\s'"<>|&;]+`)

// netTrailingPunct are characters that terminate a sentence or a bracketed
// expression rather than belonging to the URL itself.
const netTrailingPunct = ".,)]}"

// netFindURLs returns the [start, end) byte ranges of every http(s) URL in value,
// with trailing sentence punctuation trimmed off.
func netFindURLs(value string) [][2]int {
	var out [][2]int
	for _, m := range netURLPattern.FindAllStringIndex(value, -1) {
		start, end := m[0], m[1]
		for end > start && strings.IndexByte(netTrailingPunct, value[end-1]) >= 0 {
			end--
		}
		// Never reshape a payload-shaped token, even one that scans as a URL.
		if isOpaque(value[start:end]) {
			continue
		}
		out = append(out, [2]int{start, end})
	}
	return out
}

// netURL is a URL split into the pieces the mutators rewrite independently.
// Concatenating the fields reproduces the original string byte for byte.
type netURL struct {
	scheme    string // "http://" or "https://", original casing preserved
	authority string // [userinfo@]host[:port]
	path      string // leading "/" included; empty when the URL has no path
	tail      string // "?query", "#frag" or both; empty when neither is present
}

func (u netURL) String() string { return u.scheme + u.authority + u.path + u.tail }

// netSplitURL parses raw into its components. ok is false if raw is not a URL with
// a non-empty authority.
func netSplitURL(raw string) (netURL, bool) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return netURL{}, false
	}
	u := netURL{scheme: raw[:i+3]}
	rest := raw[i+3:]

	// The authority runs to the first "/", "?" or "#".
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		u.authority, rest = rest[:j], rest[j:]
	} else {
		u.authority, rest = rest, ""
	}
	if u.authority == "" {
		return netURL{}, false
	}
	// The path runs to the first "?" or "#".
	if k := strings.IndexAny(rest, "?#"); k >= 0 {
		u.path, u.tail = rest[:k], rest[k:]
	} else {
		u.path, u.tail = rest, ""
	}
	return u, true
}

// netSplitAuthority splits [userinfo@]host[:port] into its three parts. userinfo
// keeps its trailing "@" and port keeps its leading ":", so concatenating the
// results reproduces auth exactly.
func netSplitAuthority(auth string) (userinfo, host, port string) {
	if i := strings.LastIndexByte(auth, '@'); i >= 0 {
		userinfo, auth = auth[:i+1], auth[i+1:]
	}
	// An IPv6 literal is bracketed, so its internal colons are not port separators.
	if strings.HasPrefix(auth, "[") {
		if i := strings.IndexByte(auth, ']'); i >= 0 {
			return userinfo, auth[:i+1], auth[i+1:]
		}
		return userinfo, auth, ""
	}
	if i := strings.LastIndexByte(auth, ':'); i >= 0 && netAllDigits(auth[i+1:]) {
		return userinfo, auth[:i], auth[i:]
	}
	return userinfo, auth, ""
}

func netAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// netParseIPv4 parses a dotted-quad IPv4 literal into its 32-bit value. It is the
// single parser behind both ip-decimal and ip-hex.
//
// Octets with a leading zero are rejected: some resolvers read "010" as octal, so
// rewriting such a host would not provably reach the same address.
func netParseIPv4(host string) (uint32, bool) {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var v uint32
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return 0, false
		}
		if len(p) > 1 && p[0] == '0' {
			return 0, false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			c := p[i]
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return 0, false
		}
		v = v<<8 | uint32(n)
	}
	return v, true
}

// netRewriteURLs applies fn to every URL in value and splices the results back in
// place. fn returns false to decline a URL, leaving it untouched. ok is false when
// no URL was actually changed, which keeps no-op results out of the catalog.
func netRewriteURLs(value string, fn func(netURL) (netURL, bool)) (string, bool) {
	spans := netFindURLs(value)
	if len(spans) == 0 {
		return "", false
	}
	var b strings.Builder
	last := 0
	changed := false
	for _, sp := range spans {
		raw := value[sp[0]:sp[1]]
		u, ok := netSplitURL(raw)
		if !ok {
			continue
		}
		mutated, ok := fn(u)
		if !ok {
			continue
		}
		out := mutated.String()
		if out == raw {
			continue
		}
		b.WriteString(value[last:sp[0]])
		b.WriteString(out)
		last = sp[1]
		changed = true
	}
	if !changed {
		return "", false
	}
	b.WriteString(value[last:])
	return b.String(), true
}

// netRewriteHost returns a fn for netRewriteURLs that replaces a dotted-quad IPv4
// host with render(ip), leaving userinfo and port in place.
func netRewriteHost(render func(uint32) string) func(netURL) (netURL, bool) {
	return func(u netURL) (netURL, bool) {
		userinfo, host, port := netSplitAuthority(u.authority)
		ip, ok := netParseIPv4(host)
		if !ok {
			return u, false
		}
		u.authority = userinfo + render(ip) + port
		return u, true
	}
}

// --- Mutators ------------------------------------------------------------

// ipDecimal rewrites a dotted-quad host as the single integer it already encodes.
// inet_addr and every mainstream HTTP client accept http://2130706433/ and connect
// to 127.0.0.1, so the packet on the wire is unchanged; only the string in the
// command line differs. Rules that pin an indicator to a literal dotted quad miss
// it entirely.
type ipDecimal struct{}

func (ipDecimal) Name() string      { return "ip-decimal" }
func (ipDecimal) Technique() string { return "T1027.010" }
func (ipDecimal) Describe() string {
	return "Rewrite a dotted-quad IPv4 host in a URL as its 32-bit decimal form (127.0.0.1 -> 2130706433)"
}
func (ipDecimal) Remediation() string {
	return "Don't match IP literals; normalize the URL host to dotted-quad at ingest and match a derived field, or use |cidr on the parsed IP."
}

func (ipDecimal) Apply(value string) []Result {
	mutated, ok := netRewriteURLs(value, netRewriteHost(func(ip uint32) string {
		return strconv.FormatUint(uint64(ip), 10)
	}))
	if !ok {
		return nil
	}
	return []Result{{Value: mutated, Note: "rewrote the IPv4 URL host as its 32-bit decimal form"}}
}

// ipHex is ipDecimal's sibling: same parse, hexadecimal rendering. inet_addr reads
// a leading 0x as hex, so http://0x7f000001/ reaches 127.0.0.1. Listed separately
// because a rule can plausibly be hardened against one notation and not the other.
type ipHex struct{}

func (ipHex) Name() string      { return "ip-hex" }
func (ipHex) Technique() string { return "T1027.010" }
func (ipHex) Describe() string {
	return "Rewrite a dotted-quad IPv4 host in a URL as a hexadecimal dword (127.0.0.1 -> 0x7f000001)"
}
func (ipHex) Remediation() string {
	return "Same host-normalization fix; treat a URL host of 0x... or a bare 8-10 digit integer as suspicious in its own right."
}

func (ipHex) Apply(value string) []Result {
	mutated, ok := netRewriteURLs(value, netRewriteHost(func(ip uint32) string {
		return fmt.Sprintf("0x%08x", ip)
	}))
	if !ok {
		return nil
	}
	return []Result{{Value: mutated, Note: "rewrote the IPv4 URL host as a hexadecimal dword"}}
}

// urlDefaultPort spells out the port the scheme already implies. The TCP
// connection is identical, and mainstream clients elide a default port from the
// Host header, so the request on the wire is unchanged too. This defeats the very
// common rule shape that anchors on "http://host/" — the trailing slash no longer
// follows the host.
type urlDefaultPort struct{}

func (urlDefaultPort) Name() string      { return "url-default-port" }
func (urlDefaultPort) Technique() string { return "T1027.010" }
func (urlDefaultPort) Describe() string {
	return "State the scheme's default port explicitly (http -> :80, https -> :443)"
}
func (urlDefaultPort) Remediation() string {
	return "Strip default ports during URL normalization; match on the host token alone, not host + '/'."
}

func (urlDefaultPort) Apply(value string) []Result {
	mutated, ok := netRewriteURLs(value, func(u netURL) (netURL, bool) {
		var defaultPort string
		switch strings.ToLower(u.scheme) {
		case "http://":
			defaultPort = ":80"
		case "https://":
			defaultPort = ":443"
		default:
			return u, false
		}
		userinfo, host, port := netSplitAuthority(u.authority)
		if port != "" || host == "" {
			return u, false // an explicit port is already there; nothing to state
		}
		u.authority = userinfo + host + defaultPort
		return u, true
	})
	if !ok {
		return nil
	}
	return []Result{{Value: mutated, Note: "stated the scheme's default port explicitly"}}
}

// urlPercentEncode percent-encodes a couple of unreserved characters in the URL
// path. RFC 3986 section 2.3 makes an unreserved character and its percent-encoded
// octet equivalent, so the resource fetched is the same; only the bytes in the
// command line (and in the request line) change. Reserved delimiters are never
// touched, because encoding those would change the URL's structure.
type urlPercentEncode struct{}

func (urlPercentEncode) Name() string      { return "url-percent-encode" }
func (urlPercentEncode) Technique() string { return "T1027.010" }
func (urlPercentEncode) Describe() string {
	return "Percent-encode unreserved characters in a URL path (RFC 3986 makes these equivalent)"
}
func (urlPercentEncode) Remediation() string {
	return "Percent-decode URL-shaped tokens before matching, or pair URL string matches with a regex allowing %XX between characters."
}

func (urlPercentEncode) Apply(value string) []Result {
	mutated, ok := netRewriteURLs(value, func(u netURL) (netURL, bool) {
		i := strings.LastIndexByte(u.path, '/')
		if i < 0 || i == len(u.path)-1 {
			return u, false // no path, or it ends in a separator: no filename to encode
		}
		seg := u.path[i+1:]
		encoded, ok := netEncodeSegment(seg)
		if !ok {
			return u, false
		}
		u.path = u.path[:i+1] + encoded
		return u, true
	})
	if !ok {
		return nil
	}
	return []Result{{Value: mutated, Note: "percent-encoded unreserved characters in the URL path"}}
}

// netEncodeSegment percent-encodes a deterministic pair of unreserved characters in
// a single path segment: the first ASCII letter, and the dot separating an
// extension. Two targets are enough to break a literal match while keeping the
// output readable in a report.
func netEncodeSegment(seg string) (string, bool) {
	targets := map[int]bool{}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			targets[i] = true
			break
		}
	}
	// The dot before the extension, i.e. the last dot with something after it.
	if i := strings.LastIndexByte(seg, '.'); i > 0 && i < len(seg)-1 {
		targets[i] = true
	}
	if len(targets) == 0 {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if targets[i] && netUnreserved(c) {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	out := b.String()
	return out, out != seg
}

// netUnreserved reports whether c is an RFC 3986 unreserved character, the only
// class safe to percent-encode without changing what the URL means.
func netUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	}
	return false
}

// urlPathTraversal inserts a segment that immediately cancels itself. RFC 3986
// section 5.2.4 requires a client to run remove_dot_segments before issuing the
// request, so /temp/../a.exe leaves as a request for /a.exe. The command line,
// however, keeps the longer form, and a rule matching the full path stops firing.
type urlPathTraversal struct{}

func (urlPathTraversal) Name() string      { return "url-path-traversal" }
func (urlPathTraversal) Technique() string { return "T1027.010" }
func (urlPathTraversal) Describe() string {
	return "Insert a cancelling /seg/../ into a URL path (client normalizes before the request)"
}
func (urlPathTraversal) Remediation() string {
	return "Match the filename or extension alone, never the full URL path; a /../ in a command line is a strong standalone hunt."
}

func (urlPathTraversal) Apply(value string) []Result {
	mutated, ok := netRewriteURLs(value, func(u netURL) (netURL, bool) {
		i := strings.LastIndexByte(u.path, '/')
		// Require a real character on both sides of the separator: never split an
		// empty segment, and never a "//" that some clients treat as significant.
		if i < 0 || i == len(u.path)-1 {
			return u, false
		}
		if i > 0 && u.path[i-1] == '/' {
			return u, false
		}
		u.path = u.path[:i+1] + "temp/../" + u.path[i+1:]
		return u, true
	})
	if !ok {
		return nil
	}
	return []Result{{Value: mutated, Note: "inserted a self-cancelling temp/../ segment into the URL path"}}
}

// The URL and IPv4 rewrites are protocol-level: the client (curl, wget, WinINet,
// .NET, PowerShell) resolves the alternative form identically on any OS.
func (ipDecimal) Platforms() []Platform        { return []Platform{AnyOS} }
func (ipHex) Platforms() []Platform            { return []Platform{AnyOS} }
func (urlDefaultPort) Platforms() []Platform   { return []Platform{AnyOS} }
func (urlPercentEncode) Platforms() []Platform { return []Platform{AnyOS} }
func (urlPathTraversal) Platforms() []Platform { return []Platform{AnyOS} }
