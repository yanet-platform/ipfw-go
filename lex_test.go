package ipfw

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// verifies that a prefix is consumed only when the input starts with it and
// the cursor is untouched otherwise.
func Test_Prefix_Table(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		prefix string
		ok     bool
		rest   string
	}{
		{name: "match consumes the prefix", input: "add pass", prefix: "add", ok: true, rest: " pass"},
		{name: "mismatch keeps the cursor", input: "table x", prefix: "add", ok: false, rest: "table x"},
		{name: "empty prefix always matches", input: "abc", prefix: "", ok: true, rest: "abc"},
		{name: "prefix longer than the input", input: "ad", prefix: "add", ok: false, rest: "ad"},
		{name: "empty input", input: "", prefix: "add", ok: false, rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cursor := tc.input
			require.Equal(t, tc.ok, prefix(&cursor, tc.prefix))
			require.Equal(t, tc.rest, cursor)
		})
	}
}

// verifies that only spaces and tabs count as inline whitespace and that
// ws1 reports whether anything was skipped without moving on failure.
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
			cursor := tc.input
			ws0(&cursor)
			require.Equal(t, tc.rest, cursor)

			cursor = tc.input
			require.Equal(t, tc.skipped, ws1(&cursor))
			require.Equal(t, tc.rest, cursor)
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
			cursor := tc.input
			require.Equal(t, tc.token, token(&cursor))
			require.Equal(t, tc.rest, cursor)
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
			cursor := tc.input
			require.Equal(t, tc.neg, notWS1(&cursor))
			require.Equal(t, tc.rest, cursor)
		})
	}
}

// A number case shared by the three widths: the expected value when kind is
// zero, the expected kind otherwise, and the cursor afterwards.
type numberCase struct {
	name  string
	input string
	value uint64
	kind  ErrorKind
	rest  string
}

// verifies that 8-bit numbers parse up to the first non-digit and that a
// missing or overflowing number is an error that leaves the cursor alone.
func Test_ParseU8_Table(t *testing.T) {
	cases := []numberCase{
		{name: "zero", input: "0", value: 0, rest: ""},
		{name: "maximum", input: "255", value: 255, rest: ""},
		{name: "overflow by one", input: "256", kind: ErrExpectedU8, rest: "256"},
		{name: "stops at a letter", input: "12abc", value: 12, rest: "abc"},
		{name: "leading zeros", input: "007", value: 7, rest: ""},
		{name: "no digits", input: "abc", kind: ErrExpectedU8, rest: "abc"},
		{name: "empty input", input: "", kind: ErrExpectedU8, rest: ""},
		{name: "long overflow", input: "99999999999999999999999", kind: ErrExpectedU8, rest: "99999999999999999999999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cursor := tc.input
			value, kind := parseU8(&cursor)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, uint8(tc.value), value)
			require.Equal(t, tc.rest, cursor)
		})
	}
}

// verifies that 16-bit numbers parse up to the first non-digit and that a
// missing or overflowing number is an error that leaves the cursor alone.
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
			cursor := tc.input
			value, kind := parseU16(&cursor)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, uint16(tc.value), value)
			require.Equal(t, tc.rest, cursor)
		})
	}
}

// verifies that 32-bit numbers parse up to the first non-digit and that a
// missing or overflowing number is an error that leaves the cursor alone.
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
			cursor := tc.input
			value, kind := parseU32(&cursor)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, uint32(tc.value), value)
			require.Equal(t, tc.rest, cursor)
		})
	}
}

// verifies that or-delimited groups call the element parser once per element
// and report a missing separator or closing brace where it is detected.
//
// Any ASCII whitespace inside the braces is skipped. The element parser here
// consumes a run of letters, and an empty run is the element error whose
// propagation the last cases check.
func Test_OrDelimited_Table(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		elements []string
		kind     ErrorKind
		rest     string
	}{
		{name: "single element without braces", input: "a rest", elements: []string{"a"}, rest: " rest"},
		{name: "spaced group", input: "{ a or b } rest", elements: []string{"a", "b"}, rest: " rest"},
		{name: "tight group", input: "{a or b}", elements: []string{"a", "b"}, rest: ""},
		{name: "three elements", input: "{ a or b or c }", elements: []string{"a", "b", "c"}, rest: ""},
		{name: "newline inside the group", input: "{ a or\nb }", elements: []string{"a", "b"}, rest: ""},
		{name: "missing separator", input: "{ a b }", elements: []string{"a"}, kind: ErrExpectedOr, rest: "b }"},
		{name: "missing closing brace", input: "{ a", elements: []string{"a"}, kind: ErrExpectedOr, rest: ""},
		{name: "separator at end of input", input: "{ a or", elements: []string{"a"}, kind: ErrExpectedToken, rest: ""},
		{name: "element error propagates", input: "{ a or } x", elements: []string{"a"}, kind: ErrExpectedToken, rest: "} x"},
		{name: "empty group", input: "{ }", kind: ErrExpectedToken, rest: "}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cursor := tc.input
			var elements []string
			kind := orDelimited(&cursor, func(s string) (string, ErrorKind) {
				element := takeWhile(&s, isLetter)
				if element == "" {
					return s, ErrExpectedToken
				}
				elements = append(elements, element)
				return s, 0
			})
			require.Equal(t, tc.kind, kind)
			require.Equal(t, tc.elements, elements)
			require.Equal(t, tc.rest, cursor)
		})
	}
}

// isLetter is the element shape the or-delimited tests use.
func isLetter(c byte) bool {
	return c >= 'a' && c <= 'z'
}

// verifies that any 32-bit number formatted in decimal parses back to itself
// and is consumed entirely.
func Test_ParseU32_RoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		number := rapid.Uint32().Draw(t, "number")
		cursor := strconv.FormatUint(uint64(number), 10)
		value, kind := parseU32(&cursor)
		require.Equal(t, ErrorKind(0), kind)
		require.Equal(t, number, value)
		require.Empty(t, cursor)
	})
}

// verifies that any 8-bit number formatted in decimal parses back to itself
// and that a trailing non-digit suffix is left untouched.
func Test_ParseU8_RoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		number := rapid.Uint8().Draw(t, "number")
		suffix := rapid.StringMatching(`[^0-9]*`).Draw(t, "suffix")
		cursor := strconv.FormatUint(uint64(number), 10) + suffix
		value, kind := parseU8(&cursor)
		require.Equal(t, ErrorKind(0), kind)
		require.Equal(t, number, value)
		require.Equal(t, suffix, cursor)
	})
}

// verifies that a decimal above the 16-bit range is rejected without moving
// the cursor.
func Test_ParseU16_RejectsOverflow(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		number := rapid.Uint64Range(math.MaxUint16+1, math.MaxUint64).Draw(t, "number")
		input := strconv.FormatUint(number, 10)
		cursor := input
		_, kind := parseU16(&cursor)
		require.Equal(t, ErrExpectedU16, kind)
		require.Equal(t, input, cursor)
	})
}

// verifies that the taken prefix and the remaining cursor partition the
// input, with the split at the first byte failing the predicate.
func Test_TakeWhile_SplitsInput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.String().Draw(t, "input")
		cursor := input
		taken := takeWhile(&cursor, isASCIISpace)
		require.Equal(t, input, taken+cursor)
		for idx := range len(taken) {
			require.True(t, isASCIISpace(taken[idx]))
		}
		if cursor != "" {
			require.False(t, isASCIISpace(cursor[0]))
		}
	})
}

// verifies that the primitives, including an or-delimited group driven by
// a closure that captures a local, allocate nothing.
func Test_Lex_NoAllocs(t *testing.T) {
	input := "{ not tcp or 42 } rest"
	parsed := true
	allocs := testing.AllocsPerRun(100, func() {
		cursor := input
		count := 0
		kind := orDelimited(&cursor, func(s string) (string, ErrorKind) {
			notWS1(&s)
			count++
			if _, kind := parseU8(&s); kind == 0 {
				return s, 0
			}
			if token(&s) == "" {
				return s, ErrExpectedToken
			}
			return s, 0
		})
		if kind != 0 || count != 2 || !prefix(&cursor, " rest") {
			parsed = false
		}
	})
	require.True(t, parsed)
	require.Zero(t, allocs)
}
