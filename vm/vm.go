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

// Config is what a VM is built with beyond the ruleset, every part
// optional.
type Config[V4, V6 any] struct {
	// Protos resolves protocol names, nil making every name an error.
	Protos ipfw.ProtoResolver
	// Services resolves service names, nil making every name an error.
	Services ipfw.ServiceResolver
	// Hostnames resolves hostnames, nil making every hostname an error.
	Hostnames ipfw.HostnameResolver
	// CustomTarget takes targets of unknown shape, nil rejecting them.
	CustomTarget ipfw.CustomTargetFunc[V4, V6]
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
	ErrRuleNumberOrder    = errors.New("rule number goes backwards")
	ErrUnresolvedJump     = errors.New("skipto to a label that never appears")
	ErrUnresolvedProto    = errors.New("unresolved protocol name")
	ErrUnresolvedService  = errors.New("unresolved service name")
	ErrUnresolvedHostname = errors.New("unresolved hostname")
	ErrUnsupportedOption  = errors.New("unsupported option")
	ErrUnsupportedAction  = errors.New("unsupported action")
	ErrUnsupportedTarget  = errors.New("unsupported target")
	ErrUnsupportedPort    = errors.New("unsupported port")
	ErrUnsupportedRecord  = errors.New("unsupported record")
)

// BuildError is a build failure located at a line of the ruleset.
type BuildError struct {
	// Line is 1-based.
	Line int
	// Text is the line without leading and trailing whitespace.
	Text string
	// Err is the cause: a *ipfw.ParseError or one of the vm errors.
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
//
// The tokens of every rule live in one arena per kind, a rule holding the
// runs of them, so a check walks flat slices.
type VM[V4, V6 Network] struct {
	ops          []op
	ipProtos     []ipfw.ProtoIPMatch
	protos       []ipfw.ProtoMatch
	sources      []ipfw.TargetMatch[V4, V6]
	destinations []ipfw.TargetMatch[V4, V6]
	verdict      ipfw.Action
}

// span is the run of an arena holding the tokens of one rule.
type span struct {
	lo, hi int
}

// op is one rule: the record for tracing, the action, and where its
// tokens are.
type op struct {
	record       ipfw.Record
	action       ipfw.Action
	ipProtos     span
	protos       span
	sources      span
	destinations span
}

// Build reads the whole ruleset from p into a VM, networks parsed with
// nets and names resolved as cfg says.
func Build[V4, V6 Network](
	p *ipfw.Parser,
	nets ipfw.NetworkParser[V4, V6],
	cfg Config[V4, V6],
) (*VM[V4, V6], error) {
	machine := &VM[V4, V6]{verdict: cfg.DefaultVerdict}
	if machine.verdict.Kind == 0 {
		machine.verdict = ipfw.Action{Kind: ipfw.ActionDeny}
	}
	state := ipfw.NewRuleState(nets, ipfw.RuleStateConfig[V4, V6]{CustomTarget: cfg.CustomTarget})
	for {
		state.Reset()
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
			if err := machine.addRule(rec, state, &cfg); err != nil {
				return nil, &BuildError{Line: rec.Line, Text: rec.Text, Err: err}
			}
		default:
			return nil, &BuildError{Line: rec.Line, Text: rec.Text, Err: ErrUnsupportedRecord}
		}
	}
}

// addRule validates one rule and copies its tokens into the arenas.
func (m *VM[V4, V6]) addRule(rec *ipfw.Record, state *ipfw.RuleState[V4, V6], cfg *Config[V4, V6]) error {
	rule := op{record: *rec, action: rec.Instruction.Action}
	if rule.action.Kind != ipfw.ActionPass && rule.action.Kind != ipfw.ActionDeny {
		return ErrUnsupportedAction
	}
	if len(state.SourcePorts) > 0 || len(state.DestinationPorts) > 0 {
		return ErrUnsupportedPort
	}
	if len(state.Options) > 0 {
		return ErrUnsupportedOption
	}
	for _, target := range state.Sources {
		if err := checkTarget(target); err != nil {
			return err
		}
	}
	for _, target := range state.Destinations {
		if err := checkTarget(target); err != nil {
			return err
		}
	}
	rule.protos.lo = len(m.protos)
	for _, match := range state.Protos {
		resolved, err := resolveProto(match, cfg.Protos)
		if err != nil {
			return err
		}
		m.protos = append(m.protos, resolved)
	}
	rule.protos.hi = len(m.protos)
	m.ipProtos, rule.ipProtos = appendRun(m.ipProtos, state.IPProtos)
	m.sources, rule.sources = appendRun(m.sources, state.Sources)
	m.destinations, rule.destinations = appendRun(m.destinations, state.Destinations)
	m.ops = append(m.ops, rule)
	return nil
}

// appendRun appends the tokens of one rule to an arena and reports where
// they went.
func appendRun[T any](arena, tokens []T) ([]T, span) {
	lo := len(arena)
	arena = append(arena, tokens...)
	return arena, span{lo: lo, hi: len(arena)}
}

// checkTarget rejects the target kinds a check cannot match.
func checkTarget[V4, V6 any](target ipfw.TargetMatch[V4, V6]) error {
	switch target.Kind {
	case ipfw.TargetAny, ipfw.TargetNetwork4, ipfw.TargetNetwork6:
		return nil
	case ipfw.TargetHostname:
		return ErrUnresolvedHostname
	}
	return ErrUnsupportedTarget
}

// resolveProto turns a protocol name into its number through the
// resolver, a number staying as it is.
func resolveProto(match ipfw.ProtoMatch, resolver ipfw.ProtoResolver) (ipfw.ProtoMatch, error) {
	if match.Proto.IsNumber() {
		return match, nil
	}
	if resolver == nil {
		return ipfw.ProtoMatch{}, ErrUnresolvedProto
	}
	number, ok := resolver.ResolveProto(match.Proto.Name)
	if !ok {
		return ipfw.ProtoMatch{}, ErrUnresolvedProto
	}
	return ipfw.ProtoMatch{Neg: match.Neg, Proto: ipfw.Proto{Number: number}}, nil
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
		matched := m.matches(rule, pkt)
		tracer.Trace(&rule.record, rule.action, matched)
		if matched {
			return rule.action, true
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
func (m *VM[V4, V6]) matches(rule *op, pkt Packet) bool {
	if !matchIPProtos(m.ipProtos[rule.ipProtos.lo:rule.ipProtos.hi], pkt.Version()) {
		return false
	}
	if !matchProtos(m.protos[rule.protos.lo:rule.protos.hi], pkt.Protocol()) {
		return false
	}
	if !matchTargets(m.sources[rule.sources.lo:rule.sources.hi], pkt.SourceAddr()) {
		return false
	}
	return matchTargets(m.destinations[rule.destinations.lo:rule.destinations.hi], pkt.DestinationAddr())
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
func matchProtos(matches []ipfw.ProtoMatch, protocol uint8) bool {
	if len(matches) == 0 {
		return true
	}
	for _, match := range matches {
		if (match.Proto.Number == protocol) != match.Neg {
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
