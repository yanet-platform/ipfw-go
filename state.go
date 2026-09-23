package ipfw

import "slices"

// State receives the tokens of a rule body as the parser recognizes them.
//
// Callbacks are provisional until [Parser.Next] or an exported subparser
// succeeds. A later syntax or callback failure leaves earlier effects intact
// because parsing does not roll them back. Callers must discard or reset those
// effects after an error. Every callback may reject a token. [Parser.Next]
// uses a returned [ErrorKind] directly and otherwise reports [ErrState] with
// the callback error attached. Subparsers return the callback error directly.
type State interface {
	// OnIPProto receives an IP version keyword.
	OnIPProto(m ProtoIPMatch) error
	// OnProto receives a transport protocol.
	OnProto(m ProtoMatch) error
	// OnSourceTarget receives a source.
	OnSourceTarget(t Target) error
	// OnDestinationTarget receives a destination.
	OnDestinationTarget(t Target) error
	// OnSourcePort receives a source port range.
	OnSourcePort(m PortMatch) error
	// OnDestinationPort receives a destination port range.
	OnDestinationPort(m PortMatch) error
	// OnOption receives a rule option.
	OnOption(o Opt) error
}

// DiscardState accepts every token and keeps nothing.
type DiscardState struct{}

// OnIPProto implements State.
func (DiscardState) OnIPProto(ProtoIPMatch) error { return nil }

// OnProto implements State.
func (DiscardState) OnProto(ProtoMatch) error { return nil }

// OnSourceTarget implements State.
func (DiscardState) OnSourceTarget(Target) error { return nil }

// OnDestinationTarget implements State.
func (DiscardState) OnDestinationTarget(Target) error { return nil }

// OnSourcePort implements State.
func (DiscardState) OnSourcePort(PortMatch) error { return nil }

// OnDestinationPort implements State.
func (DiscardState) OnDestinationPort(PortMatch) error { return nil }

// OnOption implements State.
func (DiscardState) OnOption(Opt) error { return nil }

// ReduceState appends every token to the slice of its kind, in order.
type ReduceState struct {
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
func (m *ReduceState) Reset() {
	m.IPProtos = m.IPProtos[:0]
	m.Protos = m.Protos[:0]
	m.Sources = m.Sources[:0]
	m.Destinations = m.Destinations[:0]
	m.SourcePorts = m.SourcePorts[:0]
	m.DestinationPorts = m.DestinationPorts[:0]
	m.Options = m.Options[:0]
}

// OnIPProto implements State.
func (m *ReduceState) OnIPProto(match ProtoIPMatch) error {
	m.IPProtos = append(m.IPProtos, match)
	return nil
}

// OnProto implements State.
func (m *ReduceState) OnProto(match ProtoMatch) error {
	m.Protos = append(m.Protos, match)
	return nil
}

// OnSourceTarget implements State.
func (m *ReduceState) OnSourceTarget(target Target) error {
	m.Sources = append(m.Sources, target)
	return nil
}

// OnDestinationTarget implements State.
func (m *ReduceState) OnDestinationTarget(target Target) error {
	m.Destinations = append(m.Destinations, target)
	return nil
}

// OnSourcePort implements State.
func (m *ReduceState) OnSourcePort(match PortMatch) error {
	m.SourcePorts = append(m.SourcePorts, match)
	return nil
}

// OnDestinationPort implements State.
func (m *ReduceState) OnDestinationPort(match PortMatch) error {
	m.DestinationPorts = append(m.DestinationPorts, match)
	return nil
}

// Clone returns a copy of the state that owns every slice.
//
// The tokens themselves keep sharing the input they were parsed from, a Go
// string keeping its backing storage alive.
func (m ReduceState) Clone() ReduceState {
	return ReduceState{
		IPProtos:         slices.Clone(m.IPProtos),
		Protos:           slices.Clone(m.Protos),
		Sources:          slices.Clone(m.Sources),
		Destinations:     slices.Clone(m.Destinations),
		SourcePorts:      slices.Clone(m.SourcePorts),
		DestinationPorts: slices.Clone(m.DestinationPorts),
		Options:          slices.Clone(m.Options),
	}
}

// IsEmpty reports whether the state holds no tokens.
func (m ReduceState) IsEmpty() bool {
	return len(m.IPProtos) == 0 && len(m.Protos) == 0 && len(m.Sources) == 0 &&
		len(m.Destinations) == 0 && len(m.SourcePorts) == 0 &&
		len(m.DestinationPorts) == 0 && len(m.Options) == 0
}

// OnOption implements State.
func (m *ReduceState) OnOption(opt Opt) error {
	m.Options = append(m.Options, opt)
	return nil
}
