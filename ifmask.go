package ipfw

import "strings"

// MatchIfMask reports whether the interface name matches the fnmatch-style
// pattern of a `via` mask.
//
// `?` is one byte, `*` any run of bytes, `[…]` a class with ranges and `!`
// or `^` negation, and `\` makes the next byte literal. A star backtracks
// from the last one seen only, which is enough since a later star subsumes
// the earlier ones. An unclosed class matches nothing.
func MatchIfMask(pattern, name string) bool {
	patternIdx, nameIdx := 0, 0
	starIdx, resumeIdx := -1, -1
	for nameIdx < len(name) {
		if patternIdx < len(pattern) {
			switch pattern[patternIdx] {
			case '?':
				patternIdx++
				nameIdx++
				continue
			case '*':
				starIdx, resumeIdx = patternIdx, nameIdx
				patternIdx++
				continue
			case '[':
				if rest, ok := rangeMatch(pattern[patternIdx+1:], name[nameIdx]); ok {
					patternIdx = len(pattern) - len(rest)
					nameIdx++
					continue
				}
			case '\\':
				patternIdx++
				if patternIdx < len(pattern) && pattern[patternIdx] == name[nameIdx] {
					patternIdx++
					nameIdx++
					continue
				}
			default:
				if pattern[patternIdx] == name[nameIdx] {
					patternIdx++
					nameIdx++
					continue
				}
			}
		}
		if starIdx < 0 {
			return false
		}
		patternIdx = starIdx + 1
		resumeIdx++
		nameIdx = resumeIdx
	}
	for patternIdx < len(pattern) && pattern[patternIdx] == '*' {
		patternIdx++
	}
	return patternIdx == len(pattern)
}

// rangeMatch matches one byte against the class that follows an opening
// bracket, returning the pattern after the closing one on a match.
func rangeMatch(pattern string, c byte) (string, bool) {
	negate := false
	if pattern != "" && (pattern[0] == '!' || pattern[0] == '^') {
		pattern = pattern[1:]
		negate = true
	}
	matched := false
	idx := 0
	for {
		if idx >= len(pattern) {
			return "", false
		}
		lo := pattern[idx]
		idx++
		switch {
		case lo == ']':
			if matched != negate {
				return pattern[idx:], true
			}
			return "", false
		case lo == '\\':
			if idx >= len(pattern) {
				return "", false
			}
			if pattern[idx] == c {
				matched = true
			}
			idx++
		case idx < len(pattern) && pattern[idx] == '-':
			if idx+1 < len(pattern) && pattern[idx+1] != ']' {
				idx++
				hi := pattern[idx]
				idx++
				if hi == '\\' {
					if idx >= len(pattern) {
						return "", false
					}
					hi = pattern[idx]
					idx++
				}
				if lo <= c && c <= hi {
					matched = true
				}
			} else if lo == c {
				matched = true
			}
		case lo == c:
			matched = true
		}
	}
}

// validateIfMask rejects the mask patterns ipfw(8) does not accept: a
// double star and a class without its closing bracket.
func validateIfMask(pattern string) ErrorKind {
	idx := 0
	for idx < len(pattern) {
		switch pattern[idx] {
		case '*':
			if idx+1 < len(pattern) && pattern[idx+1] == '*' {
				return ErrExpectedIfMask
			}
			idx++
		case '[':
			if idx+4 <= len(pattern) && pattern[idx+1] == '!' {
				if close := strings.IndexByte(pattern[idx+3:], ']'); close >= 0 {
					idx += close + 4
					continue
				}
			} else if idx+3 <= len(pattern) && pattern[idx+1] != '!' {
				if close := strings.IndexByte(pattern[idx+2:], ']'); close >= 0 {
					idx += close + 3
					continue
				}
			}
			return ErrExpectedIfMask
		default:
			idx++
		}
	}
	return 0
}
