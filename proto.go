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
