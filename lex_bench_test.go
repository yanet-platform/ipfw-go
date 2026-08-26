package ipfw

import "testing"

// The benchmark results are sunk here so the compiler keeps the work.
var (
	benchRest  string
	benchKind  ErrorKind
	benchValue uint32
)

// benchElement is the element parser the group benchmark drives: an
// optional negation, then a number or a token.
func benchElement(s string) (string, fail) {
	s, _ = notWS1(s)
	if _, rest, kind := parseU8(s); kind == 0 {
		return rest, fail{}
	}
	tok, rest := token(s)
	if tok == "" {
		return s, fail{kind: ErrExpectedToken, at: s}
	}
	return rest, fail{}
}

func BenchmarkOrDelimited_Group(b *testing.B) {
	input := "{ not tcp or udp or 42 } from any to any"
	b.ReportAllocs()
	for b.Loop() {
		rest, err := orDelimited(input, benchElement)
		benchRest, benchKind = rest, err.kind
	}
}

func BenchmarkOrDelimited_Single(b *testing.B) {
	input := "tcp from any to any"
	b.ReportAllocs()
	for b.Loop() {
		rest, err := orDelimited(input, benchElement)
		benchRest, benchKind = rest, err.kind
	}
}

func BenchmarkParseU32(b *testing.B) {
	input := "4294967295 count"
	b.ReportAllocs()
	for b.Loop() {
		value, rest, kind := parseU32(input)
		benchValue, benchRest, benchKind = value, rest, kind
	}
}

func BenchmarkPrefix_WS1_Token(b *testing.B) {
	input := "add   allow tcp"
	b.ReportAllocs()
	for b.Loop() {
		rest, _ := prefix(input, "add")
		rest, _ = ws1(rest)
		_, rest = token(rest)
		benchRest = rest
	}
}
