package ipfw

import "strings"

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

func prefix(s *string, p string) bool {
	if !strings.HasPrefix(*s, p) {
		return false
	}
	*s = (*s)[len(p):]
	return true
}

func takeWhile(s *string, f func(byte) bool) string {
	str := *s
	idx := 0
	for idx < len(str) && f(str[idx]) {
		idx++
	}
	*s = str[idx:]
	return str[:idx]
}

func ws0(s *string) {
	takeWhile(s, isWS)
}

func ws1(s *string) bool {
	return takeWhile(s, isWS) != ""
}

func token(s *string) string {
	return takeWhile(s, isTokenByte)
}

func isTokenByte(c byte) bool {
	return !isASCIISpace(c)
}

// notWS1 consumes `not` only when whitespace follows, so a token that merely
// starts with the keyword, such as a protocol named `nottcp`, is left alone.
func notWS1(s *string) bool {
	saved := *s
	if prefix(s, "not") && ws1(s) {
		return true
	}
	*s = saved
	return false
}

// parseU8 stops at the first non-digit. A missing or overflowing number is an
// error that leaves the cursor untouched.
func parseU8(s *string) (uint8, ErrorKind) {
	value, ok := parseUint(s, 0xff)
	if !ok {
		return 0, ErrExpectedU8
	}
	return uint8(value), 0
}

// parseU16 is parseU8 for sixteen bits.
func parseU16(s *string) (uint16, ErrorKind) {
	value, ok := parseUint(s, 0xffff)
	if !ok {
		return 0, ErrExpectedU16
	}
	return uint16(value), 0
}

// parseU32 is parseU8 for thirty-two bits.
func parseU32(s *string) (uint32, ErrorKind) {
	value, ok := parseUint(s, 0xffffffff)
	if !ok {
		return 0, ErrExpectedU32
	}
	return uint32(value), 0
}

// parseUint checks for overflow before folding in a digit, so the value never
// wraps. Leading zeros are accepted.
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

// orDelimited parses a single element or a braced `{ a or b … }` group.
//
// The element parser takes the cursor by value and returns what it left: a
// pointer crossing an indirect call is treated as escaping by the compiler,
// which would move every caller's cursor to the heap.
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

func orElement(s *string, each func(string) (string, ErrorKind)) ErrorKind {
	rest, kind := each(*s)
	*s = rest
	return kind
}
