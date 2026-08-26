package ipfw_test

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/ipfw"
)

// verifies the glob dialect case by case: literal bytes, `?`, `*`, classes
// with ranges and negation, escapes, and the reference's mixed patterns.
func Test_MatchIfMask_Table(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		input   string
		match   bool
	}{
		{name: "literal match", pattern: "test", input: "test", match: true},
		{name: "literal mismatch", pattern: "test", input: "nottest", match: false},
		{name: "question mark in the middle", pattern: "t?st", input: "test", match: true},
		{name: "question mark first", pattern: "?est", input: "test", match: true},
		{name: "question mark last", pattern: "tes?", input: "test", match: true},
		{name: "question mark too short", pattern: "t?t", input: "test", match: false},
		{name: "question mark then a mismatch", pattern: "t?s", input: "test", match: false},
		{name: "star alone", pattern: "*", input: "test", match: true},
		{name: "star after a byte", pattern: "t*", input: "test", match: true},
		{name: "star matching nothing", pattern: "test*", input: "test", match: true},
		{name: "star in the middle", pattern: "t*t", input: "test", match: true},
		{name: "star first", pattern: "*t", input: "test", match: true},
		{name: "stars between every byte", pattern: "t*e*s*t", input: "test", match: true},
		{name: "star backtracking", pattern: "t*s", input: "tests", match: true},
		{name: "star then a mismatch", pattern: "t*b", input: "test", match: false},
		{name: "class first member", pattern: "t[ea]st", input: "test", match: true},
		{name: "class second member", pattern: "t[ea]st", input: "tast", match: true},
		{name: "class mismatch", pattern: "t[ea]st", input: "tist", match: false},
		{name: "range first", pattern: "[a-z]est", input: "test", match: true},
		{name: "range in the middle", pattern: "t[a-e]st", input: "test", match: true},
		{name: "range mismatch", pattern: "t[f-z]st", input: "test", match: false},
		{name: "negated range with a bang", pattern: "t[!a-d]st", input: "test", match: true},
		{name: "negated range with a caret", pattern: "t[^a-d]st", input: "test", match: true},
		{name: "negated range mismatch with a bang", pattern: "t[!a-e]st", input: "test", match: false},
		{name: "negated range mismatch with a caret", pattern: "t[^a-e]st", input: "test", match: false},
		{name: "escaped question mark", pattern: `t\?st`, input: "t?st", match: true},
		{name: "escaped star", pattern: `t\*st`, input: "t*st", match: true},
		{name: "escaped bracket", pattern: `t\[a]st`, input: "t[a]st", match: true},
		{name: "escaped question mark is literal", pattern: `t\?st`, input: "test", match: false},
		{name: "escaped star is literal", pattern: `t\*st`, input: "test", match: false},
		{name: "escaped bracket is literal", pattern: `t\[a]st`, input: "tast", match: false},
		{name: "mixed pattern", pattern: "a*b?cd[e-f]g", input: "axbycdeg", match: true},
		{name: "mixed pattern with an empty star", pattern: "a*b?cd[e-f]g", input: "abzcdfg", match: true},
		{name: "mixed pattern mismatch", pattern: "a*b?cd[e-f]g", input: "axbycdhg", match: false},
		{name: "suffix", pattern: "*.c", input: "foo.c", match: true},
		{name: "single byte", pattern: "?", input: "a", match: true},
		{name: "escaped question mark alone", pattern: `\?`, input: "?", match: true},
		{name: "suffix mismatch", pattern: "*.c", input: "foo.h", match: false},
		{name: "single byte against two", pattern: "?", input: "ab", match: false},
		{name: "escaped question mark alone mismatch", pattern: `\?`, input: "a", match: false},
		{name: "unclosed class never matches", pattern: "t[est", input: "test", match: false},
		{name: "trailing stars match nothing", pattern: "test**", input: "test", match: true},
		{name: "empty pattern and name", pattern: "", input: "", match: true},
		{name: "empty pattern", pattern: "", input: "a", match: false},
		{name: "star against the empty name", pattern: "*", input: "", match: true},
		{name: "trailing escape matches nothing", pattern: `a\`, input: "a", match: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.match, ipfw.MatchIfMask(tc.pattern, tc.input))
		})
	}
}

// verifies the matcher against path.Match on the dialect they share:
// literals, `?`, `*` and plain classes, no escapes and no negation.
func Test_MatchIfMask_AgainstPathMatch(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pattern := rapid.StringMatching(`([ab*?]|\[ab\]|\[a-b\]){0,8}`).Draw(t, "pattern")
		name := rapid.StringMatching(`[ab]{0,8}`).Draw(t, "name")
		expected, err := path.Match(pattern, name)
		if err != nil {
			t.Skip("pattern path.Match rejects")
		}
		require.Equal(t, expected, ipfw.MatchIfMask(pattern, name))
	})
}

// verifies that matching allocates nothing.
func Test_MatchIfMask_NoAllocs(t *testing.T) {
	matched := true
	allocs := testing.AllocsPerRun(100, func() {
		if !ipfw.MatchIfMask("vlan[0-9]*?", "vlan120") {
			matched = false
		}
	})
	require.True(t, matched)
	require.Zero(t, allocs)
}

func Fuzz_MatchIfMask(f *testing.F) {
	f.Add("t*e?t[a-z]", "test")
	f.Add(`t\[a]st`, "t[a]st")
	f.Add("[!", "x")
	f.Add("**", "")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		_ = ipfw.MatchIfMask(pattern, name)
		require.True(t, ipfw.MatchIfMask("*", name))
	})
}
