package ipfw

// ProtoIP is the set of IP versions a rule applies to, combinable as bits.
type ProtoIP uint8

// The IP versions, `ip` and `all` meaning both.
const (
	ProtoIPv4 ProtoIP = 1 << iota
	ProtoIPv6
	ProtoIPAny = ProtoIPv4 | ProtoIPv6
)

// Contains reports whether every version in o is in m.
func (m ProtoIP) Contains(o ProtoIP) bool {
	return m&o == o
}

// ProtoIPMatch is an IP version keyword of the rule body, negated by `not`.
type ProtoIPMatch struct {
	// Neg is the `not` prefix.
	Neg bool
	// Proto is the version set.
	Proto ProtoIP
}

// Proto is a transport protocol, by name or by number.
type Proto struct {
	// Name is empty for a numeric protocol.
	Name string
	// Number is the protocol number when Name is empty.
	Number uint8
}

// IsNumber reports whether the protocol was given as a number.
func (m Proto) IsNumber() bool {
	return m.Name == ""
}

// ProtoMatch is a transport protocol of the rule body, negated by `not`.
type ProtoMatch struct {
	// Neg is the `not` prefix.
	Neg bool
	// Proto is the protocol.
	Proto Proto
}

// ParseProtocols parses the protocol part of a rule body into state.
//
// It returns the number of bytes consumed, or on failure its offset together
// with the error, an ErrorKind unless the state returned something else.
func ParseProtocols(s string, state State) (int, error) {
	rest, err := parseProtocols(s, state)
	if err.Failed() {
		return len(s) - len(err.At), err.ToError()
	}
	return len(s) - len(rest), nil
}

func parseProtocols(s string, state State) (string, fail) {
	return parseProtocolElement(s, state)
}

// parseProtocolElement parses one protocol, a failure pointing at the
// element start whatever went wrong inside it.
func parseProtocolElement(s string, state State) (string, fail) {
	match, rest, kind := parseProtoMatch(s)
	if kind != 0 {
		return s, fail{Kind: ErrExpectedEitherIPOrProto, At: s}
	}
	if err := failFrom(state.Proto(match), s); err.Failed() {
		return s, err
	}
	return rest, fail{}
}

func parseProtoMatch(s string) (ProtoMatch, string, ErrorKind) {
	rest, neg := notWS1(s)
	proto, rest, kind := parseProto(rest)
	if kind != 0 {
		return ProtoMatch{}, s, kind
	}
	return ProtoMatch{Neg: neg, Proto: proto}, rest, 0
}

// parseProto reads a `[A-Za-z0-9-]+` token, a number only when every byte is
// a digit and the value fits a byte.
//
// An overflowing number is a name like any other, since custom protocols may
// be named by digits.
func parseProto(s string) (Proto, string, ErrorKind) {
	name, rest := takeWhile(s, isProtoByte)
	if name == "" {
		return Proto{}, s, ErrExpectedProto
	}
	if number, afterNumber, kind := parseU8(name); kind == 0 && afterNumber == "" {
		return Proto{Number: number}, rest, 0
	}
	return Proto{Name: name}, rest, 0
}

func isProtoByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}
