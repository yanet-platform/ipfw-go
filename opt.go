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

// parseOptionGroup parses one option or a `{ a or b … }` group of them,
// every member after the first carrying the Or flag.
func parseOptionGroup(s string, state State, hook OptionHook) (string, fail) {
	g, rest := openGroup(s)
	or := false
	for {
		buf, err := parseOption(rest, state, hook, or)
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
		or = true
	}
}

// parseOption parses one optionally negated option, the keyword matching
// by prefix and a failure pointing at the keyword.
func parseOption(s string, state State, hook OptionHook, or bool) (string, fail) {
	rest, neg := notWS1(s)
	kind, buf, ok := keywordOption(rest)
	if !ok {
		return s, fail{Kind: ErrUnknownOption, At: rest}
	}
	opt := Opt{Neg: neg, Or: or, Kind: kind}
	if err := failFrom(state.OnOption(opt), rest); err.Failed() {
		return s, err
	}
	return buf, fail{}
}

// keywordOptions are the options without an argument, in the order they
// are tried.
var keywordOptions = [...]struct {
	keyword string
	kind    OptKind
}{
	{"frag", OptFrag},
	{"established", OptEstablished},
	{"in", OptIn},
	{"out", OptOut},
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

// Add puts t into the set.
func (m *TypeSet) Add(t uint8) {
	m[t>>6] |= 1 << (t & 63)
}

// Has reports whether t is in the set.
func (m TypeSet) Has(t uint8) bool {
	return m[t>>6]&(1<<(t&63)) != 0
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
