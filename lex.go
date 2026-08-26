package ipfw

import "strings"

// isWS reports whether c separates tokens inside a line: a space or a tab.
func isWS(c byte) bool {
	return c == ' ' || c == '\t'
}

// isASCIISpace reports whether c is ASCII whitespace as the ruleset grammar
// understands it: space, tab, newline, carriage return or form feed.
//
// Vertical tab is deliberately not included, matching the set the reference
// implementation uses to delimit tokens.
func isASCIISpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	}
	return false
}

// prefix consumes p when the cursor starts with it.
func prefix(s *string, p string) bool {
	if !strings.HasPrefix(*s, p) {
		return false
	}
	*s = (*s)[len(p):]
	return true
}

// takeWhile consumes and returns the longest run of leading bytes that
// satisfy f; the result is empty when the first byte fails.
func takeWhile(s *string, f func(byte) bool) string {
	str := *s
	idx := 0
	for idx < len(str) && f(str[idx]) {
		idx++
	}
	*s = str[idx:]
	return str[:idx]
}

// ws0 skips any inline whitespace.
func ws0(s *string) {
	takeWhile(s, isWS)
}

// ws1 skips inline whitespace and reports whether there was any; the cursor
// does not move when there was none.
func ws1(s *string) bool {
	return takeWhile(s, isWS) != ""
}

// token consumes and returns the run of bytes up to the first ASCII
// whitespace; it is empty when the cursor is at whitespace or at the end.
func token(s *string) string {
	return takeWhile(s, isTokenByte)
}

// isTokenByte reports whether c can be part of a token.
func isTokenByte(c byte) bool {
	return !isASCIISpace(c)
}

// notWS1 consumes the `not` keyword together with the whitespace after it.
//
// A token that merely starts with the keyword, such as a protocol named
// `nottcp`, or the keyword at the very end of the input, is not a negation:
// the cursor is left untouched and false is returned.
func notWS1(s *string) bool {
	saved := *s
	if prefix(s, "not") && ws1(s) {
		return true
	}
	*s = saved
	return false
}

// parseU8 consumes a decimal number that fits in eight bits.
//
// The cursor stops at the first non-digit. A missing number or a value that
// does not fit is ErrExpectedU8 and leaves the cursor untouched.
func parseU8(s *string) (uint8, ErrorKind) {
	value, ok := parseUint(s, 0xff)
	if !ok {
		return 0, ErrExpectedU8
	}
	return uint8(value), 0
}

// parseU16 consumes a decimal number that fits in sixteen bits; otherwise it
// behaves like parseU8 with ErrExpectedU16.
func parseU16(s *string) (uint16, ErrorKind) {
	value, ok := parseUint(s, 0xffff)
	if !ok {
		return 0, ErrExpectedU16
	}
	return uint16(value), 0
}

// parseU32 consumes a decimal number that fits in thirty-two bits; otherwise
// it behaves like parseU8 with ErrExpectedU32.
func parseU32(s *string) (uint32, ErrorKind) {
	value, ok := parseUint(s, 0xffffffff)
	if !ok {
		return 0, ErrExpectedU32
	}
	return uint32(value), 0
}

// parseUint consumes leading decimal digits into a value no larger than max.
//
// Leading zeros are accepted. The overflow check runs before each digit is
// folded in, so the accumulator never wraps; on any failure the cursor is
// left untouched.
func parseUint(s *string, max uint64) (uint64, bool) {
	str := *s
	var value uint64
	idx := 0
	for idx < len(str) && str[idx] >= '0' && str[idx] <= '9' {
		digit := uint64(str[idx] - '0')
		if value > (max-digit)/10 {
			return 0, false
		}
		value = value*10 + digit
		idx++
	}
	if idx == 0 {
		return 0, false
	}
	*s = str[idx:]
	return value, true
}

// orDelimited parses either a single element or a braced `{ a or b … }`
// group, calling each once per element.
//
// The element parser takes the cursor by value and returns what it left: a
// pointer must not cross the indirect call, or the compiler treats it as
// escaping and moves every caller's cursor to the heap. Inside the braces
// any ASCII whitespace, newlines included, may surround the elements and
// the separators. Elements not separated by `or`, or an unclosed group,
// fail with ErrExpectedOr where the separator or the brace was expected. An
// element failure is returned as is, with the cursor where the element left it.
func orDelimited(s *string, each func(string) (string, ErrorKind)) ErrorKind {
	if !prefix(s, "{") {
		return orElement(s, each)
	}
	takeWhile(s, isASCIISpace)
	if kind := orElement(s, each); kind != 0 {
		return kind
	}
	takeWhile(s, isASCIISpace)
	for {
		if prefix(s, "}") {
			return 0
		}
		if !prefix(s, "or") {
			return ErrExpectedOr
		}
		takeWhile(s, isASCIISpace)
		if kind := orElement(s, each); kind != 0 {
			return kind
		}
		takeWhile(s, isASCIISpace)
	}
}

// orElement runs one element parser over the cursor and stores what it left.
func orElement(s *string, each func(string) (string, ErrorKind)) ErrorKind {
	rest, kind := each(*s)
	*s = rest
	return kind
}
