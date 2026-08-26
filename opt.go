package ipfw

import "strings"

// OptKind names a rule option.
type OptKind uint8

// The rule options. OptCustom is produced by an option hook.
const (
	_ OptKind = iota
	OptComment
	OptDiverted
	OptSourcePort
	OptDestinationPort
	OptEstablished
	OptFrag
	OptICMPTypes
	OptICMP6Types
	OptIn
	OptOut
	OptKeepState
	OptProto
	OptTCPFlags
	OptVia
	OptAntiSpoof
	OptCustom
)

// String returns the ipfw keyword of the option, empty for the zero value.
func (m OptKind) String() string {
	switch m {
	case OptComment:
		return "//"
	case OptDiverted:
		return "diverted"
	case OptSourcePort:
		return "src-port"
	case OptDestinationPort:
		return "dst-port"
	case OptEstablished:
		return "established"
	case OptFrag:
		return "frag"
	case OptICMPTypes:
		return "icmptypes"
	case OptICMP6Types:
		return "icmp6types"
	case OptIn:
		return "in"
	case OptOut:
		return "out"
	case OptKeepState:
		return "keep-state"
	case OptProto:
		return "proto"
	case OptTCPFlags:
		return "tcpflags"
	case OptVia:
		return "via"
	case OptAntiSpoof:
		return "antispoof"
	case OptCustom:
		return "custom"
	default:
		return ""
	}
}

// ParseOptions parses the trailing option list of a rule body into state.
//
// The hook takes the keywords the grammar does not know, nil leaving them
// unknown. It returns the number of bytes consumed, or on failure its
// offset together with the error, an ErrorKind unless the state returned
// something else.
func ParseOptions(s string, state State, hook OptionHook) (int, error) {
	rest, err := parseOptions(s, state, hook)
	return consumed(s, rest, err)
}

// parseOptions parses the option list up to the end of the input, the end
// of the line or an inline comment.
//
// Every option is handed to the state as it is read, so the ones before a
// failure stay in the state.
func parseOptions(s string, state State, hook OptionHook) (string, fail) {
	rest := s
	var ok bool
	for rest != "" && rest[0] != '\n' && !strings.HasPrefix(rest, "//") {
		buf, err := parseOptionGroup(rest, state, hook)
		if err.Failed() {
			return s, err
		}
		if rest, ok = ws1(buf); !ok {
			return rest, fail{}
		}
	}
	return rest, fail{}
}

// optionPlace is where an option stands, which decides its Or flag and
// how a negated port list is split.
type optionPlace uint8

const (
	topLevel optionPlace = iota
	groupFirst
	groupNext
)

// parseOptionGroup parses one option or a `{ a or b … }` group of them,
// every member after the first carrying the Or flag.
func parseOptionGroup(s string, state State, hook OptionHook) (string, fail) {
	g, rest := openGroup(s)
	place := topLevel
	if g.braced {
		place = groupFirst
	}
	for {
		buf, err := parseOption(rest, state, hook, place)
		if err.Failed() {
			return s, err
		}
		var more bool
		if rest, more, err = g.next(buf); err.Failed() {
			return s, err
		}
		if !more {
			return rest, fail{}
		}
		place = groupNext
	}
}

// parseOption parses one optionally negated option, the keyword matching
// by prefix and a failure pointing at the keyword.
func parseOption(s string, state State, hook OptionHook, place optionPlace) (string, fail) {
	rest, neg := notWS1(s)
	var buf string
	var err fail
	switch {
	case strings.HasPrefix(rest, "src-port"):
		buf, err = parsePortsOption(rest[len("src-port"):], state, OptSourcePort, neg, place)
	case strings.HasPrefix(rest, "dst-port"):
		buf, err = parsePortsOption(rest[len("dst-port"):], state, OptDestinationPort, neg, place)
	case strings.HasPrefix(rest, "icmptypes"):
		buf, err = parseTypesOption(rest[len("icmptypes"):], state, OptICMPTypes, neg, place)
	case strings.HasPrefix(rest, "icmptype"):
		buf, err = parseTypesOption(rest[len("icmptype"):], state, OptICMPTypes, neg, place)
	case strings.HasPrefix(rest, "keep-state"):
		buf, err = parseKeepStateOption(rest[len("keep-state"):], state, neg, place)
	case strings.HasPrefix(rest, "proto"):
		buf, err = parseProtoOption(rest[len("proto"):], state, neg, place)
	default:
		buf, err = parseKeywordOption(rest, state, neg, place)
	}
	if err.Failed() {
		return s, err
	}
	return buf, fail{}
}

// parseKeywordOption parses an option without an argument.
func parseKeywordOption(s string, state State, neg bool, place optionPlace) (string, fail) {
	kind, rest, ok := keywordOption(s)
	if !ok {
		return s, fail{Kind: ErrUnknownOption, At: s}
	}
	opt := Opt{Neg: neg, Or: place == groupNext, Kind: kind}
	if err := failFrom(state.OnOption(opt), s); err.Failed() {
		return s, err
	}
	return rest, fail{}
}

// parseTypesOption parses the comma list of type numbers after `icmptypes`
// or `icmp6types` into one option holding them as a set.
//
// A number outside the known types of the kind is an error at that number.
func parseTypesOption(s string, state State, kind OptKind, neg bool, place optionPlace) (string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	var types TypeSet
	buf := rest
	for {
		ty, afterType, numberKind := parseU8(buf)
		if numberKind != 0 {
			return s, fail{Kind: numberKind, At: buf}
		}
		if !knownType(kind, ty) {
			return s, fail{Kind: unknownTypeKind(kind), At: buf}
		}
		types.Add(ty)
		if buf, ok = prefix(afterType, ","); !ok {
			break
		}
	}
	opt := Opt{Neg: neg, Or: place == groupNext, Kind: kind, Types: types}
	if err := failFrom(state.OnOption(opt), rest); err.Failed() {
		return s, err
	}
	return buf, fail{}
}

// knownType reports whether ty is a type number ipfw(8) accepts for the
// option kind.
func knownType(kind OptKind, ty uint8) bool {
	switch kind {
	case OptICMPTypes:
		switch ty {
		case 0, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18:
			return true
		}
	case OptICMP6Types:
		return ty >= 1 && ty <= 4 || ty >= 128 && ty <= 149 || ty >= 151 && ty <= 161
	}
	return false
}

// unknownTypeKind is the error of a type number the option kind does not
// accept.
func unknownTypeKind(kind OptKind) ErrorKind {
	if kind == OptICMP6Types {
		return ErrUnknownICMP6Type
	}
	return ErrUnknownICMPType
}

// parseKeepStateOption parses the optional ` :flow` after `keep-state`.
func parseKeepStateOption(s string, state State, neg bool, place optionPlace) (string, fail) {
	flow, rest, _ := parseFlowName(s)
	opt := Opt{Neg: neg, Or: place == groupNext, Kind: OptKeepState, Text: flow}
	if err := failFrom(state.OnOption(opt), s); err.Failed() {
		return s, err
	}
	return rest, fail{}
}

// parseProtoOption parses the protocol after `proto`.
func parseProtoOption(s string, state State, neg bool, place optionPlace) (string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	proto, buf, kind := parseProto(rest)
	if kind != 0 {
		return s, fail{Kind: kind, At: rest}
	}
	opt := Opt{Neg: neg, Or: place == groupNext, Kind: OptProto, Proto: proto}
	if err := failFrom(state.OnOption(opt), rest); err.Failed() {
		return s, err
	}
	return buf, fail{}
}

// parsePortsOption parses the port list after `src-port` or `dst-port`,
// one option per range.
//
// The list is an or-group of its own, every range after the first carrying
// the Or flag. A negated list at the top level means none of the ports, so
// its ranges are separate and-terms, each one negated. Inside a group the
// negation stays on each range with the group's flags.
func parsePortsOption(
	s string,
	state State,
	kind OptKind,
	neg bool,
	place optionPlace,
) (string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	or := place == groupNext
	for {
		portRange, buf, err := parsePortRange(rest)
		if err.Failed() {
			return s, err
		}
		opt := Opt{Neg: neg, Or: or, Kind: kind, Ports: portRange}
		if err = failFrom(state.OnOption(opt), rest); err.Failed() {
			return s, err
		}
		or = !neg || place != topLevel
		if buf, ok = prefix(buf, ","); !ok {
			return buf, fail{}
		}
		rest = buf
	}
}

// keywordOptions are the options without an argument, in the order they
// are tried.
var keywordOptions = [...]struct {
	keyword string
	kind    OptKind
}{
	{"diverted", OptDiverted},
	{"frag", OptFrag},
	{"established", OptEstablished},
	{"in", OptIn},
	{"out", OptOut},
	{"antispoof", OptAntiSpoof},
}

// keywordOption tells an option without an argument by its keyword.
func keywordOption(s string) (OptKind, string, bool) {
	for idx := range keywordOptions {
		if rest, ok := prefix(s, keywordOptions[idx].keyword); ok {
			return keywordOptions[idx].kind, rest, true
		}
	}
	return 0, s, false
}

// Opt is one rule option with the argument of its kind.
type Opt struct {
	// Neg is the `not` prefix.
	Neg bool
	// Or joins the option with the previous one into an or-group.
	Or bool
	// Kind is the option.
	Kind OptKind
	// Text is the comment, the keep-state flow name or the custom keyword.
	Text string
	// Arg is the raw argument of a custom option.
	Arg string
	// Ports is the src-port or dst-port range.
	Ports PortRange
	// Proto is the proto argument.
	Proto Proto
	// Types is the icmptypes or icmp6types set.
	Types TypeSet
	// TCPFlags is the tcpflags argument.
	TCPFlags TCPFlags
	// Via is the via argument.
	Via Via
}

// TypeSet is a set of ICMP or ICMPv6 type numbers.
type TypeSet [4]uint64

// Add puts ty into the set.
func (m *TypeSet) Add(ty uint8) {
	m[ty>>6] |= 1 << (ty & 63)
}

// Has reports whether ty is in the set.
func (m TypeSet) Has(ty uint8) bool {
	return m[ty>>6]&(1<<(ty&63)) != 0
}

// IsEmpty reports whether the set has no types.
func (m TypeSet) IsEmpty() bool {
	return m == TypeSet{}
}

// TCPFlag is a TCP header flag at its wire bit position.
type TCPFlag uint8

// The TCP flags.
const (
	TCPFin TCPFlag = 1 << iota
	TCPSyn
	TCPRst
	TCPPsh
	TCPAck
	TCPUrg
)

// TCPFlags is a `tcpflags` argument: the flags that must be set among those
// in the mask.
type TCPFlags struct {
	// Set are the flags that must be set.
	Set TCPFlag
	// Mask are the flags that are examined.
	Mask TCPFlag
}

// ViaKind is how a `via` option names interfaces.
type ViaKind uint8

// The via argument kinds: an exact name, a glob mask or a table lookup.
const (
	_ ViaKind = iota
	ViaExact
	ViaMask
	ViaTable
)

// Via is the argument of a `via` option.
type Via struct {
	// Kind is how the interfaces are named.
	Kind ViaKind
	// Name is the interface name, the mask pattern or the table name.
	Name string
	// Value is the optional value of a `table(name,value)` lookup.
	Value string
}
