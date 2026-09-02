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

// TargetMatch is one typed member of a source or destination match.
type TargetMatch[V4, V6 any] struct {
	// Neg is the `not` prefix, shared by the matches of a pattern.
	Neg bool
	// Pattern is the match pattern of the target the match came from, every
	// network a name stands for sharing it. The matches of one pattern are
	// alternatives under one negation.
	Pattern uint16
	// Kind is the target kind, never a hostname or a custom one.
	Kind TargetKind
	// Name is the table name of a TargetTable.
	Name string
	// Net4 is the network of a TargetNetwork4.
	Net4 V4
	// Net6 is the network of a TargetNetwork6.
	Net6 V6
}

// ProtoNumberMatch is a transport protocol by number, negated by `not`.
type ProtoNumberMatch struct {
	// Neg is the `not` prefix.
	Neg bool
	// Number is the protocol number.
	Number uint8
}

// PortNumberMatch is an inclusive port range by number, negated by `not`.
type PortNumberMatch struct {
	// Neg is the `not` prefix.
	Neg bool
	// Lo is the first port of the range.
	Lo uint16
	// Hi is the last port of the range, Lo for a single port.
	Hi uint16
}

// VMState receives the tokens of a rule body once every name is resolved,
// which is what a VM consumes.
//
// Protocols and ports come as numbers, targets as keywords, tables and
// parsed networks, options with their protocol and port arguments as
// numbers. A Resolver turns the parser's State into it.
type VMState[V4, V6 any] interface {
	// OnIPProto receives an IP version keyword.
	OnIPProto(m ProtoIPMatch) error
	// OnProto receives a transport protocol number.
	OnProto(m ProtoNumberMatch) error
	// OnSourceTarget receives one source.
	OnSourceTarget(m TargetMatch[V4, V6]) error
	// OnDestinationTarget receives one destination.
	OnDestinationTarget(m TargetMatch[V4, V6]) error
	// OnSourcePort receives a source port range.
	OnSourcePort(m PortNumberMatch) error
	// OnDestinationPort receives a destination port range.
	OnDestinationPort(m PortNumberMatch) error
	// OnOption receives a rule option, its names resolved.
	OnOption(o Opt) error
}

// Environment is what the names of a ruleset are interpreted in.
//
// Every part but the network parser is optional, a missing one making the
// names it would resolve errors.
type Environment[V4, V6 any] struct {
	// Networks parses network text.
	Networks NetworkParser[V4, V6]
	// Protos resolves protocol names.
	Protos ProtoResolver
	// Services resolves service names.
	Services ServiceResolver
	// Targets stands hostnames and targets of unknown shape for networks.
	Targets TargetResolver[V4, V6]
}

// Resolver is the State that resolves every name of a rule body and hands
// the typed tokens to a VMState.
//
// It makes one call per token, a hostname or macro giving one call per
// network it stands for.
type Resolver[V4, V6 any] struct {
	sink        VMState[V4, V6]
	environment Environment[V4, V6]
}

// NewResolver returns a State resolving into sink within the environment.
func NewResolver[V4, V6 any](sink VMState[V4, V6], environment Environment[V4, V6]) *Resolver[V4, V6] {
	return &Resolver[V4, V6]{sink: sink, environment: environment}
}

// OnIPProto implements State.
func (m *Resolver[V4, V6]) OnIPProto(match ProtoIPMatch) error {
	return m.sink.OnIPProto(match)
}

// OnProto implements State.
func (m *Resolver[V4, V6]) OnProto(match ProtoMatch) error {
	number, err := m.resolveProto(match.Proto)
	if err != nil {
		return err
	}
	return m.sink.OnProto(ProtoNumberMatch{Neg: match.Neg, Number: number})
}

// OnSourceTarget implements State.
func (m *Resolver[V4, V6]) OnSourceTarget(target Target) error {
	return m.resolveTarget(target, sourceSide)
}

// OnDestinationTarget implements State.
func (m *Resolver[V4, V6]) OnDestinationTarget(target Target) error {
	return m.resolveTarget(target, destinationSide)
}

// OnSourcePort implements State.
func (m *Resolver[V4, V6]) OnSourcePort(match PortMatch) error {
	lo, hi, err := m.resolveRange(match.Lo, match.Hi)
	if err != nil {
		return err
	}
	return m.sink.OnSourcePort(PortNumberMatch{Neg: match.Neg, Lo: lo, Hi: hi})
}

// OnDestinationPort implements State.
func (m *Resolver[V4, V6]) OnDestinationPort(match PortMatch) error {
	lo, hi, err := m.resolveRange(match.Lo, match.Hi)
	if err != nil {
		return err
	}
	return m.sink.OnDestinationPort(PortNumberMatch{Neg: match.Neg, Lo: lo, Hi: hi})
}

// OnOption implements State, the protocol and the ports of an option
// resolved into numbers before it goes on.
func (m *Resolver[V4, V6]) OnOption(opt Opt) error {
	switch opt.Kind {
	case OptProto:
		number, err := m.resolveProto(opt.Proto)
		if err != nil {
			return err
		}
		opt.Proto = Proto{Number: number}
	case OptSourcePort, OptDestinationPort:
		lo, hi, err := m.resolveRange(opt.Ports.Lo, opt.Ports.Hi)
		if err != nil {
			return err
		}
		opt.Ports = PortRange{Lo: Port{Number: lo}, Hi: Port{Number: hi}}
	}
	return m.sink.OnOption(opt)
}

// resolveProto turns a protocol into its number, a name through the
// resolver.
func (m *Resolver[V4, V6]) resolveProto(proto Proto) (uint8, error) {
	if proto.IsNumber() {
		return proto.Number, nil
	}
	if m.environment.Protos == nil {
		return 0, ErrUnresolvedProto
	}
	number, ok := m.environment.Protos.ResolveProto(proto.Name)
	if !ok {
		return 0, ErrUnresolvedProto
	}
	return number, nil
}

// resolveRange turns both ends of a port range into numbers, a name
// through the resolver.
func (m *Resolver[V4, V6]) resolveRange(lo, hi Port) (uint16, uint16, error) {
	first, err := m.resolvePort(lo)
	if err != nil {
		return 0, 0, err
	}
	last, err := m.resolvePort(hi)
	if err != nil {
		return 0, 0, err
	}
	return first, last, nil
}

// resolvePort turns a port into its number, a name through the resolver.
func (m *Resolver[V4, V6]) resolvePort(port Port) (uint16, error) {
	if port.IsNumber() {
		return port.Number, nil
	}
	if m.environment.Services == nil {
		return 0, ErrUnresolvedService
	}
	number, ok := m.environment.Services.ResolveService(port.Name)
	if !ok {
		return 0, ErrUnresolvedService
	}
	return number, nil
}

// resolveTarget hands the typed matches of a raw target to the sink's
// callback of the side.
//
// A keyword, a table or a network is one match, a name one per network it
// stands for and none for a name standing for nothing, all of them under
// the target's pattern and negation. Rejected network text is the error
// kind of its family, a name with no resolver is ErrUnresolvedTarget.
func (m *Resolver[V4, V6]) resolveTarget(target Target, side bodySide) error {
	match := TargetMatch[V4, V6]{
		Neg:     target.Neg,
		Pattern: target.Pattern,
		Kind:    target.Kind,
	}
	switch target.Kind {
	case TargetNetwork4:
		network, err := m.environment.Networks.ParseNetwork4(target.Text)
		if err != nil {
			return ErrExpectedIPv4Network
		}
		match.Net4 = network
	case TargetNetwork6:
		network, err := m.environment.Networks.ParseNetwork6(target.Text)
		if err != nil {
			return ErrExpectedIPv6Network
		}
		match.Net6 = network
	case TargetTable:
		match.Name = target.Text
	case TargetHostname, TargetCustom:
		if m.environment.Targets == nil {
			return ErrUnresolvedTarget
		}
		nets4, nets6, err := m.environment.Targets.ResolveTarget(target)
		if err != nil {
			return err
		}
		for _, network := range nets4 {
			match = TargetMatch[V4, V6]{
				Neg:     target.Neg,
				Pattern: target.Pattern,
				Kind:    TargetNetwork4,
				Net4:    network,
			}
			if err := m.emitTarget(side, match); err != nil {
				return err
			}
		}
		for _, network := range nets6 {
			match = TargetMatch[V4, V6]{
				Neg:     target.Neg,
				Pattern: target.Pattern,
				Kind:    TargetNetwork6,
				Net6:    network,
			}
			if err := m.emitTarget(side, match); err != nil {
				return err
			}
		}
		return nil
	}
	return m.emitTarget(side, match)
}

// emitTarget hands the match to the sink's callback of the side.
func (m *Resolver[V4, V6]) emitTarget(side bodySide, match TargetMatch[V4, V6]) error {
	switch side {
	case sourceSide:
		return m.sink.OnSourceTarget(match)
	case destinationSide:
		return m.sink.OnDestinationTarget(match)
	}
	return nil
}

// ReduceVMState appends every typed token to the slice of its kind, in
// order.
type ReduceVMState[V4, V6 any] struct {
	// IPProtos holds the IP version keywords.
	IPProtos []ProtoIPMatch
	// Protos holds the transport protocol numbers.
	Protos []ProtoNumberMatch
	// Sources holds the sources.
	Sources []TargetMatch[V4, V6]
	// Destinations holds the destinations.
	Destinations []TargetMatch[V4, V6]
	// SourcePorts holds the source port ranges.
	SourcePorts []PortNumberMatch
	// DestinationPorts holds the destination port ranges.
	DestinationPorts []PortNumberMatch
	// Options holds the rule options.
	Options []Opt
}

// Reset empties every slice and keeps its capacity for the next line.
func (m *ReduceVMState[V4, V6]) Reset() {
	m.IPProtos = m.IPProtos[:0]
	m.Protos = m.Protos[:0]
	m.Sources = m.Sources[:0]
	m.Destinations = m.Destinations[:0]
	m.SourcePorts = m.SourcePorts[:0]
	m.DestinationPorts = m.DestinationPorts[:0]
	m.Options = m.Options[:0]
}

// OnIPProto implements VMState.
func (m *ReduceVMState[V4, V6]) OnIPProto(match ProtoIPMatch) error {
	m.IPProtos = append(m.IPProtos, match)
	return nil
}

// OnProto implements VMState.
func (m *ReduceVMState[V4, V6]) OnProto(match ProtoNumberMatch) error {
	m.Protos = append(m.Protos, match)
	return nil
}

// OnSourceTarget implements VMState.
func (m *ReduceVMState[V4, V6]) OnSourceTarget(match TargetMatch[V4, V6]) error {
	m.Sources = append(m.Sources, match)
	return nil
}

// OnDestinationTarget implements VMState.
func (m *ReduceVMState[V4, V6]) OnDestinationTarget(match TargetMatch[V4, V6]) error {
	m.Destinations = append(m.Destinations, match)
	return nil
}

// OnSourcePort implements VMState.
func (m *ReduceVMState[V4, V6]) OnSourcePort(match PortNumberMatch) error {
	m.SourcePorts = append(m.SourcePorts, match)
	return nil
}

// OnDestinationPort implements VMState.
func (m *ReduceVMState[V4, V6]) OnDestinationPort(match PortNumberMatch) error {
	m.DestinationPorts = append(m.DestinationPorts, match)
	return nil
}

// OnOption implements VMState.
func (m *ReduceVMState[V4, V6]) OnOption(opt Opt) error {
	m.Options = append(m.Options, opt)
	return nil
}
