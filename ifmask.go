package ipfw

// MatchIfMask reports whether the interface name matches the fnmatch-style
// pattern of a `via` mask.
//
// `?` is one byte, `*` any run of bytes, `[…]` a class with ranges and `!`
// or `^` negation, and `\` makes the next byte literal. A star backtracks
// from the last one seen only, which is enough since a later star subsumes
// the earlier ones. A malformed class makes its opening bracket literal.
func MatchIfMask(pattern, name string) bool {
	patternIdx, nameIdx := 0, 0
	starIdx, resumeIdx := -1, -1
	literalBracketIdx := len(pattern)
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
				if patternIdx < literalBracketIdx {
					rest, result := rangeMatch(pattern[patternIdx+1:], name[nameIdx])
					if result == rangeMatched {
						patternIdx = len(pattern) - len(rest)
						nameIdx++
						continue
					}
					if result == rangeMismatch {
						break
					}
					// No later class can close within a suffix that this scan exhausted.
					literalBracketIdx = patternIdx
				}
				if name[nameIdx] == '[' {
					patternIdx++
					nameIdx++
					continue
				}
			case '\\':
				patternIdx++
				if patternIdx == len(pattern) {
					if name[nameIdx] == '\\' {
						nameIdx++
						continue
					}
					break
				}
				if pattern[patternIdx] == name[nameIdx] {
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

type rangeMatchResult uint8

const (
	rangeMalformed rangeMatchResult = iota
	rangeMismatch
	rangeMatched
)

// rangeMatch distinguishes a malformed class from a complete mismatch.
// The remaining pattern is returned only on a match.
func rangeMatch(pattern string, c byte) (string, rangeMatchResult) {
	negate := false
	if pattern != "" && (pattern[0] == '!' || pattern[0] == '^') {
		pattern = pattern[1:]
		negate = true
	}
	matched := false
	idx := 0
	for {
		if idx >= len(pattern) {
			return "", rangeMalformed
		}
		lo := pattern[idx]
		idx++
		escaped := lo == '\\'
		if escaped {
			if idx >= len(pattern) {
				return "", rangeMalformed
			}
			lo = pattern[idx]
			idx++
		}
		switch {
		// A closing bracket is literal when it is the first class member.
		case !escaped && lo == ']' && idx > 1:
			if matched != negate {
				return pattern[idx:], rangeMatched
			}
			return "", rangeMismatch
		case idx < len(pattern) && pattern[idx] == '-':
			if idx+1 < len(pattern) && pattern[idx+1] != ']' {
				idx++
				hi := pattern[idx]
				idx++
				if hi == '\\' {
					if idx >= len(pattern) {
						return "", rangeMalformed
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
