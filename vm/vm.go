package vm

import (
	"errors"
	"net/netip"
	"strconv"

	"github.com/yanet-platform/ipfw"
)

// Network is what the matcher needs from a network type.
type Network interface {
	// ContainsAddr reports whether addr belongs to the network.
	ContainsAddr(addr netip.Addr) bool
}

// TableRegistry holds the tables of a ruleset, filled while building and
// consulted while matching.
type TableRegistry[V4, V6 any] interface {
	// LookupNetwork reports whether addr is in the table, false when the
	// table does not exist.
	LookupNetwork(table string, addr netip.Addr) bool
	// LookupInterface reports the value of an interface in the table.
	LookupInterface(table, ifname string) (string, bool)
	// AddNetwork4 adds an IPv4 network to the table.
	AddNetwork4(table string, network V4)
	// AddNetwork6 adds an IPv6 network to the table.
	AddNetwork6(table string, network V6)
	// AddInterface adds an interface with its value to the table.
	AddInterface(table, ifname, value string)
}

// Tracer sees every rule a check evaluates.
type Tracer interface {
	// Trace is called with the rule's record, its action and whether it
	// matched the packet.
	Trace(rec *ipfw.Record, action ipfw.Action, matched bool)
}

// UnresolvedJumps is what a `skipto` to a label that never appears does.
type UnresolvedJumps uint8

// The policies: an error when building, or falling through at check time.
const (
	UnresolvedJumpsError UnresolvedJumps = iota
	UnresolvedJumpsFallThrough
)

// OptionMatcher decides whether a custom option matches a packet.
type OptionMatcher func(opt ipfw.Opt, ctx *Context, pkt Packet) bool

// Config is what a VM is built with beyond the ruleset and its resolvers,
// every part optional.
type Config[V4, V6 any] struct {
	// Tables is the table registry, nil meaning a fresh default one.
	Tables TableRegistry[V4, V6]
	// DefaultVerdict is the action when no rule matches, the zero value
	// meaning deny.
	DefaultVerdict ipfw.Action
	// UnresolvedJumps is the policy for jumps to a label that never appears.
	UnresolvedJumps UnresolvedJumps
	// OptionMatcher matches custom options, nil making them a build error.
	OptionMatcher OptionMatcher
}

// The errors a build reports, wrapped in a BuildError.
var (
	ErrRuleNumberOrder   = errors.New("rule number goes backwards")
	ErrUnresolvedJump    = errors.New("skipto to a label that never appears")
	ErrUnsupportedOption = errors.New("unsupported option")
	ErrUnsupportedAction = errors.New("unsupported action")
	ErrUnsupportedTarget = errors.New("unsupported target")
	ErrUnsupportedPort   = errors.New("unsupported port")
	ErrUnsupportedRecord = errors.New("unsupported record")
)

// BuildError is a build failure located at a line of the ruleset.
type BuildError struct {
	// Line is 1-based.
	Line int
	// Text is the line without leading and trailing whitespace.
	Text string
	// Err is the cause: a *ipfw.ParseError, which wraps a vm error when a
	// token is one the VM does not take, or a vm error of the whole line.
	Err error
}

// Error renders the line, its text and the cause.
func (m *BuildError) Error() string {
	return strconv.Itoa(m.Line) + ": " + m.Text + ": " + m.Err.Error()
}

// Unwrap returns the cause.
func (m *BuildError) Unwrap() error {
	return m.Err
}

// VM evaluates packets against a built ruleset. Check is safe for
// concurrent use.
type VM[V4, V6 Network] struct {
	ops     []op[V4, V6]
	verdict ipfw.Action
}

// op is one rule: the record for tracing, the action and the typed tokens
// of the body as the resolver handed them over.
type op[V4, V6 Network] struct {
	// Record is the line the rule came from.
	Record ipfw.Record
	// Action is what a match does.
	Action ipfw.Action
	// IPProtos are the IP version sets, none meaning any version.
	IPProtos []ipfw.ProtoIPMatch
	// Protos are the transport protocol numbers, none meaning any protocol.
	Protos []ipfw.ProtoNumberMatch
	// Sources are the sources, none matching nothing.
	Sources []ipfw.TargetMatch[V4, V6]
	// Destinations are the destinations, none matching nothing.
	Destinations []ipfw.TargetMatch[V4, V6]
}

// Build reads the whole ruleset from p into a VM, every name resolved
// with resolvers on the way in.
func Build[V4, V6 Network](
	p *ipfw.Parser,
	resolvers ipfw.Resolvers[V4, V6],
	cfg Config[V4, V6],
) (*VM[V4, V6], error) {
	machine := &VM[V4, V6]{verdict: cfg.DefaultVerdict}
	if machine.verdict.Kind == 0 {
		machine.verdict = ipfw.Action{Kind: ipfw.ActionDeny}
	}
	var sink builder[V4, V6]
	state := ipfw.NewResolver(&sink, resolvers)
	for {
		sink.Rule = op[V4, V6]{}
		rec, parseErr := p.Next(state)
		if parseErr != nil {
			return nil, &BuildError{Line: parseErr.Line, Text: parseErr.Text, Err: parseErr}
		}
		switch rec.Kind {
		case ipfw.RecordEOF:
			return machine, nil
		case ipfw.RecordEmpty, ipfw.RecordComment:
			continue
		case ipfw.RecordInstruction:
			rule := sink.Rule
			rule.Record, rule.Action = *rec, rec.Instruction.Action
			if rule.Action.Kind != ipfw.ActionPass && rule.Action.Kind != ipfw.ActionDeny {
				return nil, &BuildError{Line: rec.Line, Text: rec.Text, Err: ErrUnsupportedAction}
			}
			machine.ops = append(machine.ops, rule)
		default:
			return nil, &BuildError{Line: rec.Line, Text: rec.Text, Err: ErrUnsupportedRecord}
		}
	}
}

// builder is the VMState a build reads a line into.
//
// It collects the tokens of the rule under construction and rejects the
// ones the VM does not take yet, which the parser then positions at the
// token.
type builder[V4, V6 Network] struct {
	// Rule is the rule under construction.
	Rule op[V4, V6]
}

// OnIPProto implements ipfw.VMState.
func (m *builder[V4, V6]) OnIPProto(match ipfw.ProtoIPMatch) error {
	m.Rule.IPProtos = append(m.Rule.IPProtos, match)
	return nil
}

// OnProto implements ipfw.VMState.
func (m *builder[V4, V6]) OnProto(match ipfw.ProtoNumberMatch) error {
	m.Rule.Protos = append(m.Rule.Protos, match)
	return nil
}

// OnSourceTarget implements ipfw.VMState.
func (m *builder[V4, V6]) OnSourceTarget(match ipfw.TargetMatch[V4, V6]) error {
	if err := checkTarget(match); err != nil {
		return err
	}
	m.Rule.Sources = append(m.Rule.Sources, match)
	return nil
}

// OnDestinationTarget implements ipfw.VMState.
func (m *builder[V4, V6]) OnDestinationTarget(match ipfw.TargetMatch[V4, V6]) error {
	if err := checkTarget(match); err != nil {
		return err
	}
	m.Rule.Destinations = append(m.Rule.Destinations, match)
	return nil
}

// OnSourcePort implements ipfw.VMState.
func (m *builder[V4, V6]) OnSourcePort(ipfw.PortNumberMatch) error {
	return ErrUnsupportedPort
}

// OnDestinationPort implements ipfw.VMState.
func (m *builder[V4, V6]) OnDestinationPort(ipfw.PortNumberMatch) error {
	return ErrUnsupportedPort
}

// OnOption implements ipfw.VMState.
func (m *builder[V4, V6]) OnOption(ipfw.Opt) error {
	return ErrUnsupportedOption
}

// checkTarget rejects the target kinds a check cannot match yet.
func checkTarget[V4, V6 any](target ipfw.TargetMatch[V4, V6]) error {
	switch target.Kind {
	case ipfw.TargetAny, ipfw.TargetNetwork4, ipfw.TargetNetwork6:
		return nil
	}
	return ErrUnsupportedTarget
}

// Len is the number of rules.
func (m *VM[V4, V6]) Len() int {
	return len(m.ops)
}

// Check runs the packet through the rules and returns the verdict, the
// default one when no rule terminates the search.
func (m *VM[V4, V6]) Check(ctx *Context, pkt Packet) ipfw.Action {
	if action, matched := m.CheckTrace(ctx, pkt, nopTracer{}); matched {
		return action
	}
	return m.verdict
}

// CheckTrace is Check reporting every rule evaluated to tracer, and
// whether a rule terminated the search.
func (m *VM[V4, V6]) CheckTrace(ctx *Context, pkt Packet, tracer Tracer) (ipfw.Action, bool) {
	for pc := 0; pc < len(m.ops); pc++ {
		rule := &m.ops[pc]
		matched := rule.matches(pkt)
		tracer.Trace(&rule.Record, rule.Action, matched)
		if matched {
			return rule.Action, true
		}
	}
	return ipfw.Action{}, false
}

// nopTracer is the tracer of Check.
type nopTracer struct{}

// Trace implements Tracer.
func (nopTracer) Trace(*ipfw.Record, ipfw.Action, bool) {}

// matches reports whether the packet satisfies the body of the rule: the
// IP versions, the protocols, the sources and the destinations.
func (m *op[V4, V6]) matches(pkt Packet) bool {
	if !matchIPProtos(m.IPProtos, pkt.Version()) {
		return false
	}
	if !matchProtos(m.Protos, pkt.Protocol()) {
		return false
	}
	if !matchTargets(m.Sources, pkt.SourceAddr()) {
		return false
	}
	return matchTargets(m.Destinations, pkt.DestinationAddr())
}

// matchIPProtos reports whether the version is in one of the version
// sets, no set meaning any version.
//
// A version that is neither IPv4 nor IPv6 matches no set.
func matchIPProtos(matches []ipfw.ProtoIPMatch, version IPVersion) bool {
	if len(matches) == 0 {
		return true
	}
	var bit ipfw.ProtoIP
	switch version {
	case IPv4:
		bit = ipfw.ProtoIPv4
	case IPv6:
		bit = ipfw.ProtoIPv6
	default:
		return false
	}
	for _, match := range matches {
		if match.Proto.Contains(bit) != match.Neg {
			return true
		}
	}
	return false
}

// matchProtos reports whether the protocol is one of the protocols, none
// meaning any protocol.
func matchProtos(matches []ipfw.ProtoNumberMatch, protocol uint8) bool {
	if len(matches) == 0 {
		return true
	}
	for _, match := range matches {
		if (match.Number == protocol) != match.Neg {
			return true
		}
	}
	return false
}

// matchTargets reports whether the address is one of the targets, none
// matching nothing.
//
// A side left empty by an unresolvable name is a rule that never matches.
func matchTargets[V4, V6 Network](targets []ipfw.TargetMatch[V4, V6], addr netip.Addr) bool {
	for _, target := range targets {
		if matchTarget(target, addr) != target.Neg {
			return true
		}
	}
	return false
}

// matchTarget reports whether the address is the target's.
func matchTarget[V4, V6 Network](target ipfw.TargetMatch[V4, V6], addr netip.Addr) bool {
	switch target.Kind {
	case ipfw.TargetAny:
		return true
	case ipfw.TargetNetwork4:
		return addr.Is4() && target.Net4.ContainsAddr(addr)
	case ipfw.TargetNetwork6:
		return addr.Is6() && target.Net6.ContainsAddr(addr)
	}
	return false
}
