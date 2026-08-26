package ipfw

// State receives the tokens of a rule body as the parser recognizes them.
//
// Every callback may reject a token: an ErrorKind becomes a ParseError of
// that kind at the token, any other error is attached to an ErrState.
type State interface {
	// IPProto receives an IP version keyword.
	IPProto(m ProtoIPMatch) error
	// Proto receives a transport protocol.
	Proto(m ProtoMatch) error
	// SourceTarget receives a source.
	SourceTarget(t Target) error
	// DestinationTarget receives a destination.
	DestinationTarget(t Target) error
	// SourcePort receives a source port range.
	SourcePort(m PortMatch) error
	// DestinationPort receives a destination port range.
	DestinationPort(m PortMatch) error
	// Option receives a rule option.
	Option(o Opt) error
}

// DiscardState accepts every token and keeps nothing.
type DiscardState struct{}

// IPProto implements State.
func (DiscardState) IPProto(ProtoIPMatch) error { return nil }

// Proto implements State.
func (DiscardState) Proto(ProtoMatch) error { return nil }

// SourceTarget implements State.
func (DiscardState) SourceTarget(Target) error { return nil }

// DestinationTarget implements State.
func (DiscardState) DestinationTarget(Target) error { return nil }

// SourcePort implements State.
func (DiscardState) SourcePort(PortMatch) error { return nil }

// DestinationPort implements State.
func (DiscardState) DestinationPort(PortMatch) error { return nil }

// Option implements State.
func (DiscardState) Option(Opt) error { return nil }

// CollectState appends every token to the slice of its kind, in order.
type CollectState struct {
	// IPProtos holds the IP version keywords.
	IPProtos []ProtoIPMatch
	// Protos holds the transport protocols.
	Protos []ProtoMatch
	// Sources holds the sources.
	Sources []Target
	// Destinations holds the destinations.
	Destinations []Target
	// SourcePorts holds the source port ranges.
	SourcePorts []PortMatch
	// DestinationPorts holds the destination port ranges.
	DestinationPorts []PortMatch
	// Options holds the rule options.
	Options []Opt
}

// Reset empties every slice and keeps its capacity for the next line.
func (m *CollectState) Reset() {
	m.IPProtos = m.IPProtos[:0]
	m.Protos = m.Protos[:0]
	m.Sources = m.Sources[:0]
	m.Destinations = m.Destinations[:0]
	m.SourcePorts = m.SourcePorts[:0]
	m.DestinationPorts = m.DestinationPorts[:0]
	m.Options = m.Options[:0]
}

// IPProto implements State.
func (m *CollectState) IPProto(match ProtoIPMatch) error {
	m.IPProtos = append(m.IPProtos, match)
	return nil
}

// Proto implements State.
func (m *CollectState) Proto(match ProtoMatch) error {
	m.Protos = append(m.Protos, match)
	return nil
}

// SourceTarget implements State.
func (m *CollectState) SourceTarget(target Target) error {
	m.Sources = append(m.Sources, target)
	return nil
}

// DestinationTarget implements State.
func (m *CollectState) DestinationTarget(target Target) error {
	m.Destinations = append(m.Destinations, target)
	return nil
}

// SourcePort implements State.
func (m *CollectState) SourcePort(match PortMatch) error {
	m.SourcePorts = append(m.SourcePorts, match)
	return nil
}

// DestinationPort implements State.
func (m *CollectState) DestinationPort(match PortMatch) error {
	m.DestinationPorts = append(m.DestinationPorts, match)
	return nil
}

// Option implements State.
func (m *CollectState) Option(opt Opt) error {
	m.Options = append(m.Options, opt)
	return nil
}
