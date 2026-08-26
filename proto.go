package ipfw

// ProtoIP is the set of IP versions a rule applies to, combinable as bits.
type ProtoIP uint8

// The IP versions, `ip` and `all` meaning both.
const (
	ProtoIPv4 ProtoIP = 1 << iota
	ProtoIPv6
	ProtoIPAny = ProtoIPv4 | ProtoIPv6
)

// ParseProtoIP recognizes the exact IP version keywords `ip`, `all`, `ip4`,
// `ipv4`, `ip6` and `ipv6`.
func ParseProtoIP(token string) (ProtoIP, bool) {
	switch token {
	case "ip", "all":
		return ProtoIPAny, true
	case "ip4", "ipv4":
		return ProtoIPv4, true
	case "ip6", "ipv6":
		return ProtoIPv6, true
	default:
		return 0, false
	}
}

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
	return consumed(s, rest, err)
}

// parseProtocols parses one protocol or a `{ a or b … }` group of them, the
// list being an alternative by nature so no grouping is conveyed.
func parseProtocols(s string, state State) (string, fail) {
	return orDelimited(s, func(element string) (string, fail) {
		return parseProtocolElement(element, state)
	})
}

// parseProtocolElement parses one protocol, a failure pointing at the
// element start whatever went wrong inside it.
//
// The whole token decides between an IP version keyword and a transport
// protocol, which is how `ip` and `ipencap` are told apart.
func parseProtocolElement(s string, state State) (string, fail) {
	rest, neg := notWS1(s)
	proto, rest, kind := parseProto(rest)
	if kind != 0 {
		return s, fail{Kind: ErrExpectedEitherIPOrProto, At: s}
	}
	var err error
	if version, ok := ParseProtoIP(proto.Name); ok {
		err = state.IPProto(ProtoIPMatch{Neg: neg, Proto: version})
	} else {
		err = state.Proto(ProtoMatch{Neg: neg, Proto: proto})
	}
	if failure := failFrom(err, s); failure.Failed() {
		return s, failure
	}
	return rest, fail{}
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
