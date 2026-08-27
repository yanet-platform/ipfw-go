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

// TargetResolver turns a target the parser could only name, a hostname or
// a target of unknown shape, into the networks it stands for.
type TargetResolver[V4, V6 any] interface {
	// ResolveTarget returns the networks of both families the target stands
	// for, none meaning a target that matches nothing.
	//
	// An error rejects the target, an ErrorKind keeping its kind. The
	// slices belong to the resolver and are read before its next call.
	ResolveTarget(target Target) ([]V4, []V6, error)
}

// TargetMatch is a typed source or destination: a keyword, a table or a
// parsed network of the consumer's types.
type TargetMatch[V4, V6 any] struct {
	// Neg is the `not` prefix.
	Neg bool
	// Kind is the target kind, never a hostname or a custom one.
	Kind TargetKind
	// Name is the table name of a TargetTable.
	Name string
	// Net4 is the network of a TargetNetwork4.
	Net4 V4
	// Net6 is the network of a TargetNetwork6.
	Net6 V6
}

// RuleState is the State that turns the raw tokens of a rule into typed
// values, networks parsed with the consumer's types.
//
// A hostname or a target of unknown shape becomes the networks its
// resolver stands it for, one match each. Protocol and service names stay
// names, the VM resolving them when it builds.
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

	nets    NetworkParser[V4, V6]
	targets TargetResolver[V4, V6]
}

// NewRuleState returns a state parsing networks with nets, targets
// resolving hostnames and targets of unknown shape and nil rejecting them.
func NewRuleState[V4, V6 any](nets NetworkParser[V4, V6], targets TargetResolver[V4, V6]) *RuleState[V4, V6] {
	return &RuleState[V4, V6]{nets: nets, targets: targets}
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
	sources, err := m.appendTarget(m.Sources, target)
	if err != nil {
		return err
	}
	m.Sources = sources
	return nil
}

// OnDestinationTarget implements State.
func (m *RuleState[V4, V6]) OnDestinationTarget(target Target) error {
	destinations, err := m.appendTarget(m.Destinations, target)
	if err != nil {
		return err
	}
	m.Destinations = destinations
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

// appendTarget appends the typed matches of a raw target, one for a
// keyword, a table or a network, one per network of a resolved name.
//
// Rejected network text is the error kind of its family, a name with no
// resolver is ErrUnresolvedTarget.
func (m *RuleState[V4, V6]) appendTarget(
	matches []TargetMatch[V4, V6],
	target Target,
) ([]TargetMatch[V4, V6], error) {
	match := TargetMatch[V4, V6]{Neg: target.Neg, Kind: target.Kind}
	switch target.Kind {
	case TargetNetwork4:
		network, err := m.nets.ParseNetwork4(target.Text)
		if err != nil {
			return matches, ErrExpectedIPv4Network
		}
		match.Net4 = network
	case TargetNetwork6:
		network, err := m.nets.ParseNetwork6(target.Text)
		if err != nil {
			return matches, ErrExpectedIPv6Network
		}
		match.Net6 = network
	case TargetTable:
		match.Name = target.Text
	case TargetHostname, TargetCustom:
		if m.targets == nil {
			return matches, ErrUnresolvedTarget
		}
		nets4, nets6, err := m.targets.ResolveTarget(target)
		if err != nil {
			return matches, err
		}
		for _, network := range nets4 {
			matches = append(matches, TargetMatch[V4, V6]{Neg: target.Neg, Kind: TargetNetwork4, Net4: network})
		}
		for _, network := range nets6 {
			matches = append(matches, TargetMatch[V4, V6]{Neg: target.Neg, Kind: TargetNetwork6, Net6: network})
		}
		return matches, nil
	}
	return append(matches, match), nil
}
