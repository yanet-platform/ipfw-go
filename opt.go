package ipfw

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
