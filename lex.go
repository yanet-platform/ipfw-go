package ipfw

import "strings"

// fail is a parse failure inside a line, the zero value being success.
type fail struct {
	// Kind is what went wrong.
	Kind ErrorKind
	// At is the input left at the point of detection, from which the line
	// parser derives the column.
	At string
	// Err is the error a State or a hook returned, set with ErrState.
	Err error
}

// Failed reports whether the value describes a failure.
func (m fail) Failed() bool {
	return m.Kind != 0
}

func isWS(c byte) bool {
	return c == ' ' || c == '\t'
}

// isASCIISpace deliberately excludes vertical tab, like the reference grammar.
func isASCIISpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	}
	return false
}

func prefix(s, p string) (string, bool) {
	if !strings.HasPrefix(s, p) {
		return s, false
	}
	return s[len(p):], true
}

func takeWhile(s string, f func(byte) bool) (string, string) {
	idx := 0
	for idx < len(s) && f(s[idx]) {
		idx++
	}
	return s[:idx], s[idx:]
}

func ws0(s string) string {
	_, rest := takeWhile(s, isWS)
	return rest
}

func ws1(s string) (string, bool) {
	taken, rest := takeWhile(s, isWS)
	return rest, taken != ""
}

func skipSpace(s string) string {
	_, rest := takeWhile(s, isASCIISpace)
	return rest
}

func token(s string) (string, string) {
	return takeWhile(s, isTokenByte)
}

func isTokenByte(c byte) bool {
	return !isASCIISpace(c)
}

// notWS1 consumes `not` only when whitespace follows, so a token that merely
// starts with the keyword, such as a protocol named `nottcp`, is left alone.
func notWS1(s string) (string, bool) {
	rest, ok := prefix(s, "not")
	if !ok {
		return s, false
	}
	rest, ok = ws1(rest)
	if !ok {
		return s, false
	}
	return rest, true
}

// parseU8 stops at the first non-digit. A missing or overflowing number is an
// error, and the input is returned unchanged.
func parseU8(s string) (uint8, string, ErrorKind) {
	value, rest, ok := parseUint(s, 0xff)
	if !ok {
		return 0, s, ErrExpectedU8
	}
	return uint8(value), rest, 0
}

// parseU16 is parseU8 for sixteen bits.
func parseU16(s string) (uint16, string, ErrorKind) {
	value, rest, ok := parseUint(s, 0xffff)
	if !ok {
		return 0, s, ErrExpectedU16
	}
	return uint16(value), rest, 0
}

// parseU32 is parseU8 for thirty-two bits.
func parseU32(s string) (uint32, string, ErrorKind) {
	value, rest, ok := parseUint(s, 0xffffffff)
	if !ok {
		return 0, s, ErrExpectedU32
	}
	return uint32(value), rest, 0
}

// parseUint checks for overflow before folding in a digit, so the value never
// wraps. Leading zeros are accepted.
func parseUint(s string, max uint64) (uint64, string, bool) {
	var value uint64
	idx := 0
	for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
		digit := uint64(s[idx] - '0')
		if value > (max-digit)/10 {
			return 0, s, false
		}
		value = value*10 + digit
		idx++
	}
	if idx == 0 {
		return 0, s, false
	}
	return value, s[idx:], true
}

// orDelimited parses a single element or a braced `{ a or b … }` group.
//
// Any ASCII whitespace may surround the elements and the separators inside
// the braces. On failure the whole input is returned and the failure carries
// where it was detected.
func orDelimited(s string, each func(string) (string, fail)) (string, fail) {
	rest, ok := prefix(s, "{")
	if !ok {
		return orElement(s, each)
	}
	rest, err := orElement(skipSpace(rest), each)
	if err.Failed() {
		return s, err
	}
	rest = skipSpace(rest)
	for {
		if closed, done := prefix(rest, "}"); done {
			return closed, fail{}
		}
		rest, ok = prefix(rest, "or")
		if !ok {
			return s, fail{Kind: ErrExpectedOr, At: rest}
		}
		rest, err = orElement(skipSpace(rest), each)
		if err.Failed() {
			return s, err
		}
		rest = skipSpace(rest)
	}
}

func orElement(s string, each func(string) (string, fail)) (string, fail) {
	rest, err := each(s)
	if err.Failed() {
		return s, err
	}
	return rest, fail{}
}
