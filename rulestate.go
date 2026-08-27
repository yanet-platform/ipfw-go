package ipfw

import "net/netip"

// NetworkParser turns network text into the network types of a consumer,
// V4 and V6, and builds host networks from resolved addresses.
type NetworkParser[V4, V6 any] interface {
	// ParseNetwork4 parses IPv4 network text.
	ParseNetwork4(s string) (V4, error)
	// ParseNetwork6 parses IPv6 network text.
	ParseNetwork6(s string) (V6, error)
	// Network4FromAddr is the host network of an IPv4 address.
	Network4FromAddr(a netip.Addr) (V4, error)
	// Network6FromAddr is the host network of an IPv6 address.
	Network6FromAddr(a netip.Addr) (V6, error)
}

// NetworkParserFuncs is a NetworkParser made of four functions, so a
// network library plugs in without an adapter type.
//
// The zero value panics on use.
type NetworkParserFuncs[V4, V6 any] struct {
	// Parse4 parses IPv4 network text.
	Parse4 func(string) (V4, error)
	// Parse6 parses IPv6 network text.
	Parse6 func(string) (V6, error)
	// FromAddr4 is the host network of an IPv4 address.
	FromAddr4 func(netip.Addr) (V4, error)
	// FromAddr6 is the host network of an IPv6 address.
	FromAddr6 func(netip.Addr) (V6, error)
}

// ParseNetwork4 implements NetworkParser.
func (m NetworkParserFuncs[V4, V6]) ParseNetwork4(s string) (V4, error) {
	return m.Parse4(s)
}

// ParseNetwork6 implements NetworkParser.
func (m NetworkParserFuncs[V4, V6]) ParseNetwork6(s string) (V6, error) {
	return m.Parse6(s)
}

// Network4FromAddr implements NetworkParser.
func (m NetworkParserFuncs[V4, V6]) Network4FromAddr(a netip.Addr) (V4, error) {
	return m.FromAddr4(a)
}

// Network6FromAddr implements NetworkParser.
func (m NetworkParserFuncs[V4, V6]) Network6FromAddr(a netip.Addr) (V6, error) {
	return m.FromAddr6(a)
}

// ProtoResolver turns a protocol name into its number.
type ProtoResolver interface {
	// ResolveProto reports the number of a protocol name, false when unknown.
	ResolveProto(name string) (uint8, bool)
}

// ServiceResolver turns a service name into its port.
type ServiceResolver interface {
	// ResolveService reports the port of a service name, false when unknown.
	ResolveService(name string) (uint16, bool)
}

// HostnameResolver turns a hostname into its addresses.
type HostnameResolver interface {
	// ResolveHostname reports the addresses of a hostname, false when unknown.
	ResolveHostname(name string) ([]netip.Addr, bool)
}

// TargetMatch is a typed source or destination: a keyword, a name or a
// parsed network of the consumer's types.
type TargetMatch[V4, V6 any] struct {
	// Neg is the `not` prefix.
	Neg bool
	// Kind is the target kind.
	Kind TargetKind
	// Name is the hostname or the table name.
	Name string
	// Net4 is the network of a TargetNetwork4.
	Net4 V4
	// Net6 is the network of a TargetNetwork6.
	Net6 V6
}

// CustomTargetFunc turns a target of unknown shape into a typed one, the
// negation being its to copy.
//
// An error rejects the target, an ErrorKind keeping its kind.
type CustomTargetFunc[V4, V6 any] func(t Target) (TargetMatch[V4, V6], error)

// RuleState is the State that turns the raw tokens of a rule into typed
// values, networks parsed with the consumer's types.
//
// Names stay names: protocol, service and hostname resolution is the
// consumer's, the VM doing it when it builds.
type RuleState[V4, V6 any] struct {
	// IPProtos holds the IP version keywords.
	IPProtos []ProtoIPMatch
	// Protos holds the transport protocols.
	Protos []ProtoMatch
	// Sources holds the sources.
	Sources []TargetMatch[V4, V6]
	// Destinations holds the destinations.
	Destinations []TargetMatch[V4, V6]
	// SourcePorts holds the source port ranges.
	SourcePorts []PortMatch
	// DestinationPorts holds the destination port ranges.
	DestinationPorts []PortMatch
	// Options holds the rule options.
	Options []Opt

	nets   NetworkParser[V4, V6]
	custom CustomTargetFunc[V4, V6]
}

// NewRuleState returns a state parsing networks with nets, custom taking
// the targets of unknown shape and nil rejecting them.
func NewRuleState[V4, V6 any](nets NetworkParser[V4, V6], custom CustomTargetFunc[V4, V6]) *RuleState[V4, V6] {
	return &RuleState[V4, V6]{nets: nets, custom: custom}
}

// Reset empties every slice and keeps its capacity for the next line.
func (m *RuleState[V4, V6]) Reset() {
	m.IPProtos = m.IPProtos[:0]
	m.Protos = m.Protos[:0]
	m.Sources = m.Sources[:0]
	m.Destinations = m.Destinations[:0]
	m.SourcePorts = m.SourcePorts[:0]
	m.DestinationPorts = m.DestinationPorts[:0]
	m.Options = m.Options[:0]
}

// OnIPProto implements State.
func (m *RuleState[V4, V6]) OnIPProto(match ProtoIPMatch) error {
	m.IPProtos = append(m.IPProtos, match)
	return nil
}

// OnProto implements State.
func (m *RuleState[V4, V6]) OnProto(match ProtoMatch) error {
	m.Protos = append(m.Protos, match)
	return nil
}

// OnSourceTarget implements State.
func (m *RuleState[V4, V6]) OnSourceTarget(target Target) error {
	match, err := m.typedTarget(target)
	if err != nil {
		return err
	}
	m.Sources = append(m.Sources, match)
	return nil
}

// OnDestinationTarget implements State.
func (m *RuleState[V4, V6]) OnDestinationTarget(target Target) error {
	match, err := m.typedTarget(target)
	if err != nil {
		return err
	}
	m.Destinations = append(m.Destinations, match)
	return nil
}

// OnSourcePort implements State.
func (m *RuleState[V4, V6]) OnSourcePort(match PortMatch) error {
	m.SourcePorts = append(m.SourcePorts, match)
	return nil
}

// OnDestinationPort implements State.
func (m *RuleState[V4, V6]) OnDestinationPort(match PortMatch) error {
	m.DestinationPorts = append(m.DestinationPorts, match)
	return nil
}

// OnOption implements State.
func (m *RuleState[V4, V6]) OnOption(opt Opt) error {
	m.Options = append(m.Options, opt)
	return nil
}

// typedTarget turns a raw target into a typed one, network text parsed
// with the consumer's parser.
//
// A rejected text is the error kind of its family.
func (m *RuleState[V4, V6]) typedTarget(target Target) (TargetMatch[V4, V6], error) {
	match := TargetMatch[V4, V6]{Neg: target.Neg, Kind: target.Kind}
	switch target.Kind {
	case TargetNetwork4:
		network, err := m.nets.ParseNetwork4(target.Text)
		if err != nil {
			return TargetMatch[V4, V6]{}, ErrExpectedIPv4Network
		}
		match.Net4 = network
	case TargetNetwork6:
		network, err := m.nets.ParseNetwork6(target.Text)
		if err != nil {
			return TargetMatch[V4, V6]{}, ErrExpectedIPv6Network
		}
		match.Net6 = network
	case TargetHostname, TargetTable:
		match.Name = target.Text
	case TargetCustom:
		if m.custom == nil {
			return TargetMatch[V4, V6]{}, ErrExpectedTarget
		}
		return m.custom(target)
	}
	return match, nil
}
