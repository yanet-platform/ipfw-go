package ipfw

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// verifies that a prefix is consumed only when the input starts with it and
// the input is returned unchanged otherwise.
func Test_Prefix_Table(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		prefix string
		ok     bool
		rest   string
	}{
		{
			name:   "match consumes the prefix",
			input:  "add pass",
			prefix: "add",
			ok:     true,
			rest:   " pass",
		},
		{
			name:   "mismatch returns the input",
			input:  "table x",
			prefix: "add",
			ok:     false,
			rest:   "table x",
		},
		{name: "empty prefix always matches", input: "abc", prefix: "", ok: true, rest: "abc"},
		{name: "prefix longer than the input", input: "ad", prefix: "add", ok: false, rest: "ad"},
		{name: "empty input", input: "", prefix: "add", ok: false, rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rest, ok := prefix(tc.input, tc.prefix)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that only spaces and tabs count as inline whitespace and that
// ws1 reports whether anything was skipped.
func Test_WS_Table(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		skipped bool
		rest    string
	}{
		{name: "spaces", input: "   x", skipped: true, rest: "x"},
		{name: "tabs", input: "\t\tx", skipped: true, rest: "x"},
		{name: "mixed", input: " \t x", skipped: true, rest: "x"},
		{name: "none", input: "x y", skipped: false, rest: "x y"},
		{name: "newline is not inline whitespace", input: "\n x", skipped: false, rest: "\n x"},
		{name: "empty input", input: "", skipped: false, rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.rest, ws0(tc.input))

			rest, ok := ws1(tc.input)
			require.Equal(t, tc.skipped, ok)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that a token runs up to the first ASCII whitespace byte and is
// empty when the input starts with one.
func Test_Token_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		token string
		rest  string
	}{
		{name: "stops at space", input: "abc def", token: "abc", rest: " def"},
		{name: "stops at tab", input: "a\tb", token: "a", rest: "\tb"},
		{name: "stops at newline", input: "abc\n", token: "abc", rest: "\n"},
		{name: "stops at carriage return", input: "abc\rx", token: "abc", rest: "\rx"},
		{name: "stops at form feed", input: "abc\fx", token: "abc", rest: "\fx"},
		{name: "vertical tab is not whitespace", input: "a\vb c", token: "a\vb", rest: " c"},
		{name: "whole input", input: "abc", token: "abc", rest: ""},
		{name: "leading whitespace yields nothing", input: " abc", token: "", rest: " abc"},
		{name: "empty input", input: "", token: "", rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, rest := token(tc.input)
			require.Equal(t, tc.token, tok)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that a negation is only the keyword followed by whitespace, so a
// token merely starting with "not" is left for the caller.
func Test_NotWS1_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		neg   bool
		rest  string
	}{
		{name: "not then space", input: "not tcp", neg: true, rest: "tcp"},
		{name: "not then tab", input: "not\ttcp", neg: true, rest: "tcp"},
		{name: "glued keyword is a token", input: "nottcp", neg: false, rest: "nottcp"},
		{name: "bare keyword at end", input: "not", neg: false, rest: "not"},
		{name: "keyword then newline", input: "not\ntcp", neg: false, rest: "not\ntcp"},
		{name: "other token", input: "tcp", neg: false, rest: "tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rest, neg := notWS1(tc.input)
			require.Equal(t, tc.neg, neg)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that a trailing keyword is taken only behind whitespace, by
// prefix, and that the input is returned unchanged otherwise.
func Test_WS1Keyword_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		ok    bool
		rest  string
	}{
		{name: "space then keyword", input: " log x", ok: true, rest: " x"},
		{name: "tab then keyword", input: "\tlog", ok: true, rest: ""},
		{name: "keyword matches by prefix", input: " logamount", ok: true, rest: "amount"},
		{name: "keyword without whitespace", input: "log x", ok: false, rest: "log x"},
		{name: "whitespace then another word", input: " tag", ok: false, rest: " tag"},
		{name: "whitespace alone", input: " ", ok: false, rest: " "},
		{name: "empty input", input: "", ok: false, rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rest, ok := ws1Keyword(tc.input, "log")
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// A number case shared by the three widths: the expected value when kind is
// zero, the expected kind otherwise, and the rest afterwards.
type numberCase struct {
	name  string
	input string
	value uint64
	kind  ErrorKind
	rest  string
}

// verifies that 8-bit numbers parse up to the first non-digit and that a
// missing or overflowing number is an error that returns the input unchanged.
func Test_ParseU8_Table(t *testing.T) {
	cases := []numberCase{
		{name: "zero", input: "0", value: 0, rest: ""},
		{name: "maximum", input: "255", value: 255, rest: ""},
		{name: "overflow by one", input: "256", kind: ErrExpectedU8, rest: "256"},
		{name: "stops at a letter", input: "12abc", value: 12, rest: "abc"},
		{name: "leading zeros", input: "007", value: 7, rest: ""},
		{name: "no digits", input: "abc", kind: ErrExpectedU8, rest: "abc"},
		{name: "empty input", input: "", kind: ErrExpectedU8, rest: ""},
		{
			name:  "long overflow",
			input: "99999999999999999999999",
			kind:  ErrExpectedU8,
			rest:  "99999999999999999999999",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, rest, kind := parseU8(tc.input)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, uint8(tc.value), value)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that 16-bit numbers parse up to the first non-digit and that a
// missing or overflowing number is an error that returns the input unchanged.
func Test_ParseU16_Table(t *testing.T) {
	cases := []numberCase{
		{name: "zero", input: "0", value: 0, rest: ""},
		{name: "maximum", input: "65535", value: 65535, rest: ""},
		{name: "overflow by one", input: "65536", kind: ErrExpectedU16, rest: "65536"},
		{name: "stops at a dash", input: "22-53", value: 22, rest: "-53"},
		{name: "leading zeros", input: "007", value: 7, rest: ""},
		{name: "no digits", input: "abc", kind: ErrExpectedU16, rest: "abc"},
		{name: "empty input", input: "", kind: ErrExpectedU16, rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, rest, kind := parseU16(tc.input)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, uint16(tc.value), value)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that 32-bit numbers parse up to the first non-digit and that a
// missing or overflowing number is an error that returns the input unchanged.
func Test_ParseU32_Table(t *testing.T) {
	cases := []numberCase{
		{name: "zero", input: "0", value: 0, rest: ""},
		{name: "maximum", input: "4294967295", value: 4294967295, rest: ""},
		{name: "overflow by one", input: "4294967296", kind: ErrExpectedU32, rest: "4294967296"},
		{name: "stops at a space", input: "1500 count", value: 1500, rest: " count"},
		{name: "leading zeros", input: "007", value: 7, rest: ""},
		{name: "no digits", input: "abc", kind: ErrExpectedU32, rest: "abc"},
		{name: "empty input", input: "", kind: ErrExpectedU32, rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, rest, kind := parseU32(tc.input)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, uint32(tc.value), value)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that a group opens on a brace, the spaces after it skipped, and
// that anything else is a lone element left untouched.
func Test_OpenGroup_Table(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		braced bool
		rest   string
	}{
		{name: "brace then space", input: "{ a or b }", braced: true, rest: "a or b }"},
		{name: "tight brace", input: "{a or b}", braced: true, rest: "a or b}"},
		{name: "newline after the brace", input: "{\n\ta }", braced: true, rest: "a }"},
		{name: "brace at end of input", input: "{", braced: true, rest: ""},
		{name: "lone element", input: "a rest", braced: false, rest: "a rest"},
		{name: "lone element keeps its spaces", input: " a", braced: false, rest: " a"},
		{name: "empty input", input: "", braced: false, rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, rest := openGroup(tc.input)
			require.Equal(t, tc.braced, g.Braced)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that after an element a braced group goes on at `or` and ends at
// `}`, fails with ErrExpectedOr otherwise, and a lone element just ends.
//
// The spaces after `or` are skipped and the failure points at the first
// non-space byte, the input coming back unchanged.
func Test_Group_Next_Table(t *testing.T) {
	cases := []struct {
		name   string
		braced bool
		input  string
		rest   string
		more   bool
		kind   ErrorKind
		at     string
	}{
		{name: "or then space", braced: true, input: " or b }", rest: "b }", more: true},
		{name: "tight or", braced: true, input: "or b}", rest: "b}", more: true},
		{name: "newlines around or", braced: true, input: "\nor\n\tb }", rest: "b }", more: true},
		{name: "or at end of input", braced: true, input: " or", rest: "", more: true},
		{name: "closing brace", braced: true, input: " } rest", rest: " rest", more: false},
		{name: "tight closing brace", braced: true, input: "}", rest: "", more: false},
		{name: "closing brace after a newline", braced: true, input: "\n}", rest: "", more: false},
		{
			name:   "missing separator",
			braced: true,
			input:  " b }",
			rest:   " b }",
			kind:   ErrExpectedOr,
			at:     "b }",
		},
		{
			name:   "missing closing brace",
			braced: true,
			input:  "",
			rest:   "",
			kind:   ErrExpectedOr,
			at:     "",
		},
		{
			name:   "spaces then end of input",
			braced: true,
			input:  " \n",
			rest:   " \n",
			kind:   ErrExpectedOr,
			at:     "",
		},
		{name: "lone element", braced: false, input: " rest", rest: " rest", more: false},
		{name: "lone element before or", braced: false, input: " or b", rest: " or b", more: false},
		{name: "lone element at end of input", braced: false, input: "", rest: "", more: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rest, more, err := group{Braced: tc.braced}.Next(tc.input)
			require.Equal(t, tc.kind, err.Kind)
			require.Equal(t, tc.at, err.At)
			require.Equal(t, tc.more, more)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that a group driven the way the parsers drive theirs sees each
// element once and on failure returns the whole input, pointing at the fault.
//
// Any ASCII whitespace inside the braces is skipped. The element here is a
// run of letters, and an empty run is the element error whose propagation
// the last cases check.
func Test_Group_Loop_Table(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		elements []string
		kind     ErrorKind
		at       string
		rest     string
	}{
		{
			name:     "single element without braces",
			input:    "a rest",
			elements: []string{"a"},
			rest:     " rest",
		},
		{
			name:     "spaced group",
			input:    "{ a or b } rest",
			elements: []string{"a", "b"},
			rest:     " rest",
		},
		{name: "tight group", input: "{a or b}", elements: []string{"a", "b"}, rest: ""},
		{
			name:     "three elements",
			input:    "{ a or b or c }",
			elements: []string{"a", "b", "c"},
			rest:     "",
		},
		{
			name:     "newline inside the group",
			input:    "{ a or\nb }",
			elements: []string{"a", "b"},
			rest:     "",
		},
		{
			name:     "missing separator",
			input:    "{ a b }",
			elements: []string{"a"},
			kind:     ErrExpectedOr,
			at:       "b }",
			rest:     "{ a b }",
		},
		{
			name:     "missing closing brace",
			input:    "{ a",
			elements: []string{"a"},
			kind:     ErrExpectedOr,
			at:       "",
			rest:     "{ a",
		},
		{
			name:     "separator at end of input",
			input:    "{ a or",
			elements: []string{"a"},
			kind:     ErrExpectedToken,
			at:       "",
			rest:     "{ a or",
		},
		{
			name:     "element error propagates",
			input:    "{ a or } x",
			elements: []string{"a"},
			kind:     ErrExpectedToken,
			at:       "} x",
			rest:     "{ a or } x",
		},
		{name: "empty group", input: "{ }", kind: ErrExpectedToken, at: "}", rest: "{ }"},
		{name: "single element error", input: "1", kind: ErrExpectedToken, at: "1", rest: "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rest, elements, err := groupLetters(tc.input)
			require.Equal(t, tc.kind, err.Kind)
			require.Equal(t, tc.at, err.At)
			require.Equal(t, tc.elements, elements)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// groupLetters drives a group of letter runs the way the parsers drive
// theirs and collects the elements it saw.
func groupLetters(s string) (string, []string, fail) {
	var elements []string
	g, rest := openGroup(s)
	for {
		element, afterElement := takeWhile(rest, isLetter)
		if element == "" {
			return s, elements, fail{Kind: ErrExpectedToken, At: rest}
		}
		elements = append(elements, element)
		var more bool
		var err fail
		rest, more, err = g.Next(afterElement)
		if err.Failed() {
			return s, elements, err
		}
		if !more {
			return rest, elements, fail{}
		}
	}
}

// isLetter is the element shape the group loop test uses.
func isLetter(c byte) bool {
	return c >= 'a' && c <= 'z'
}

// verifies that any 32-bit number formatted in decimal parses back to itself
// and is consumed entirely.
func Test_ParseU32_RoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		number := rapid.Uint32().Draw(t, "number")
		value, rest, kind := parseU32(strconv.FormatUint(uint64(number), 10))
		require.Equal(t, ErrorKind(0), kind)
		require.Equal(t, number, value)
		require.Empty(t, rest)
	})
}

// verifies that any 8-bit number formatted in decimal parses back to itself
// and that a trailing non-digit suffix is left untouched.
func Test_ParseU8_RoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		number := rapid.Uint8().Draw(t, "number")
		suffix := rapid.StringMatching(`[^0-9]*`).Draw(t, "suffix")
		value, rest, kind := parseU8(strconv.FormatUint(uint64(number), 10) + suffix)
		require.Equal(t, ErrorKind(0), kind)
		require.Equal(t, number, value)
		require.Equal(t, suffix, rest)
	})
}

// verifies that a decimal above the 16-bit range is rejected and the input
// comes back unchanged.
func Test_ParseU16_RejectsOverflow(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		number := rapid.Uint64Range(math.MaxUint16+1, math.MaxUint64).Draw(t, "number")
		input := strconv.FormatUint(number, 10)
		_, rest, kind := parseU16(input)
		require.Equal(t, ErrExpectedU16, kind)
		require.Equal(t, input, rest)
	})
}

// verifies that the taken prefix and the rest partition the input, with the
// split at the first byte failing the predicate.
func Test_TakeWhile_SplitsInput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.String().Draw(t, "input")
		taken, rest := takeWhile(input, isASCIISpace)
		require.Equal(t, input, taken+rest)
		for idx := range len(taken) {
			require.True(t, isASCIISpace(taken[idx]))
		}
		if rest != "" {
			require.False(t, isASCIISpace(rest[0]))
		}
	})
}

// verifies that driving a braced group and its elements allocates nothing.
func Test_Group_NoAllocs(t *testing.T) {
	input := "{ not tcp or 42 } rest"
	parsed := true
	allocs := testing.AllocsPerRun(100, func() {
		rest, count, err := groupElements(input)
		if err.Failed() || count != 2 || rest != " rest" {
			parsed = false
		}
	})
	require.True(t, parsed)
	require.Zero(t, allocs)
}

// groupElements drives a group over benchElement the way the parsers drive
// theirs and counts the elements.
func groupElements(s string) (string, int, fail) {
	count := 0
	g, rest := openGroup(s)
	for {
		afterElement, err := benchElement(rest)
		if err.Failed() {
			return s, count, err
		}
		count++
		var more bool
		rest, more, err = g.Next(afterElement)
		if err.Failed() {
			return s, count, err
		}
		if !more {
			return rest, count, fail{}
		}
	}
}

// The benchmark results are sunk here so the compiler keeps the work.
var (
	benchRest  string
	benchKind  ErrorKind
	benchValue uint32
)

// benchElement is the element the group benchmarks drive: an optional
// negation, then a number or a token.
func benchElement(s string) (string, fail) {
	s, _ = notWS1(s)
	if _, rest, kind := parseU8(s); kind == 0 {
		return rest, fail{}
	}
	tok, rest := token(s)
	if tok == "" {
		return s, fail{Kind: ErrExpectedToken, At: s}
	}
	return rest, fail{}
}

func Benchmark_Group_Braced(b *testing.B) {
	input := "{ not tcp or udp or 42 } from any to any"
	b.ReportAllocs()
	for b.Loop() {
		rest, _, err := groupElements(input)
		benchRest, benchKind = rest, err.Kind
	}
}

func Benchmark_Group_Lone(b *testing.B) {
	input := "tcp from any to any"
	b.ReportAllocs()
	for b.Loop() {
		rest, _, err := groupElements(input)
		benchRest, benchKind = rest, err.Kind
	}
}

func Benchmark_ParseU32_Maximum(b *testing.B) {
	input := "4294967295 count"
	b.ReportAllocs()
	for b.Loop() {
		value, rest, kind := parseU32(input)
		benchValue, benchRest, benchKind = value, rest, kind
	}
}

func Benchmark_Lex_KeywordSequence(b *testing.B) {
	input := "add   allow tcp"
	b.ReportAllocs()
	for b.Loop() {
		rest, _ := prefix(input, "add")
		rest, _ = ws1(rest)
		_, rest = token(rest)
		benchRest = rest
	}
}
