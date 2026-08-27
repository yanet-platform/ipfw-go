package vm

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

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

// UnresolvedJumps is what a skipto no later rule or label satisfies does.
type UnresolvedJumps uint8

// The policies: an error when building, or falling through at check time.
const (
	UnresolvedJumpsError UnresolvedJumps = iota
	UnresolvedJumpsFallThrough
)

// OptionMatcher decides whether a custom option, its negation aside, holds
// for a packet in the context.
//
// It runs on the match path and must not allocate.
type OptionMatcher func(opt ipfw.Opt, ctx *Context, pkt Packet) bool

// Config is what a VM is built with beyond the ruleset and its resolvers,
// every part optional.
type Config[V4, V6 any] struct {
	// Tables is the table registry, nil meaning a fresh default one.
	Tables TableRegistry[V4, V6]
	// DefaultVerdict is the action when no rule matches, the zero value
	// meaning deny.
	DefaultVerdict ipfw.Action
	// UnresolvedJumps is the policy for a skipto no later rule or label
	// satisfies.
	UnresolvedJumps UnresolvedJumps
	// OptionMatcher matches custom options, nil making them a build error.
	OptionMatcher OptionMatcher
}

// The errors a build reports, wrapped in a BuildError.
var (
	ErrRuleNumberOrder   = errors.New("rule number goes backwards")
	ErrUnresolvedJump    = errors.New("skipto to a rule that never appears")
	ErrUnsupportedOption = errors.New("unsupported option")
	ErrUnsupportedAction = errors.New("unsupported action")
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
//
// The VM is stateless: a matching count rule goes on with the next rule
// without counting anything, and a check-state rule, having no body, never
// matches.
type VM[V4, V6 Network] struct {
	ops     []op[V4, V6]
	labels  map[string]int
	tables  TableRegistry[V4, V6]
	matcher OptionMatcher
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
	// SourcePorts are the source port ranges, none meaning any port, some
	// requiring the packet to have ports.
	SourcePorts []ipfw.PortNumberMatch
	// DestinationPorts are the destination port ranges, likewise.
	DestinationPorts []ipfw.PortNumberMatch
	// Options are the rule options in order, AND-ed except inside an
	// or-group.
	Options []ipfw.Opt
	// Jump is the index of the rule a matching skipto continues at, always
	// past this one: the next rule until the jump is linked.
	Jump int
}

// Build reads the whole ruleset from p into a VM, every name resolved
// with resolvers on the way in.
func Build[V4, V6 Network](
	p *ipfw.Parser,
	resolvers ipfw.Resolvers[V4, V6],
	cfg Config[V4, V6],
) (*VM[V4, V6], error) {
	machine := &VM[V4, V6]{tables: cfg.Tables, matcher: cfg.OptionMatcher, verdict: cfg.DefaultVerdict}
	if machine.tables == nil {
		machine.tables = NewTables[V4, V6]()
	}
	if machine.verdict.Kind == 0 {
		machine.verdict = ipfw.Action{Kind: ipfw.ActionDeny}
	}
	sink := newBuilder(machine.tables, resolvers.Networks, cfg.OptionMatcher != nil)
	state := ipfw.NewResolver(sink, resolvers)
	for {
		rec, parseErr := p.Next(state)
		if parseErr != nil {
			return nil, &BuildError{Line: parseErr.Line, Text: parseErr.Text, Err: parseErr}
		}
		switch rec.Kind {
		case ipfw.RecordEOF:
			if unresolved, ok := sink.Unresolved(); ok && cfg.UnresolvedJumps == UnresolvedJumpsError {
				return nil, &BuildError{Line: unresolved.Line, Text: unresolved.Text, Err: ErrUnresolvedJump}
			}
			machine.ops, machine.labels = sink.Ops(), sink.Labels()
			return machine, nil
		case ipfw.RecordEmpty, ipfw.RecordComment:
			continue
		case ipfw.RecordInstruction:
			if err := sink.Add(rec); err != nil {
				return nil, &BuildError{Line: rec.Line, Text: rec.Text, Err: err}
			}
		case ipfw.RecordLabel:
			sink.Label(rec.Label)
		case ipfw.RecordTable:
			if err := sink.Table(&rec.Table); err != nil {
				return nil, &BuildError{Line: rec.Line, Text: rec.Text, Err: err}
			}
		default:
			return nil, &BuildError{Line: rec.Line, Text: rec.Text, Err: ErrUnsupportedRecord}
		}
	}
}

// builder is the VMState a build reads a line into and the assembler of
// the rule list.
//
// It collects the tokens of the rule under construction and rejects the
// ones the VM does not take yet, which the parser then positions at the
// token. Add turns the collected tokens into a rule, numbering it and
// linking the jumps, Label links the jumps to a label, Table fills the
// registry.
type builder[V4, V6 Network] struct {
	// Rule is the rule under construction.
	Rule     op[V4, V6]
	ops      []op[V4, V6]
	tables   TableRegistry[V4, V6]
	networks ipfw.NetworkParser[V4, V6]
	// custom is whether a custom option has a matcher to go to.
	custom bool
	// number is the rule number the next instruction gets, an explicit one
	// moving it forward.
	number uint32
	// labels is the index of the rule after each label, the last
	// occurrence winning.
	labels map[string]int
	// pendingNumbers and pendingLabels hold, by rule number and by label,
	// the indexes of the skipto rules waiting for them.
	pendingNumbers map[uint32][]int
	pendingLabels  map[string][]int
}

func newBuilder[V4, V6 Network](
	tables TableRegistry[V4, V6],
	networks ipfw.NetworkParser[V4, V6],
	custom bool,
) *builder[V4, V6] {
	return &builder[V4, V6]{
		tables:         tables,
		networks:       networks,
		custom:         custom,
		number:         1,
		labels:         map[string]int{},
		pendingNumbers: map[uint32][]int{},
		pendingLabels:  map[string][]int{},
	}
}

// Add appends the instruction just read with the tokens collected for it
// and starts the next rule.
//
// An explicit rule number below the running one is ErrRuleNumberOrder, an
// action the VM cannot run ErrUnsupportedAction. A skipto falls through to
// the next rule until the rule numbered so, or the label, comes after it
// and links the jump, so every jump goes forward.
func (m *builder[V4, V6]) Add(rec *ipfw.Record) error {
	if num := rec.Instruction.Num; num != 0 {
		if num < m.number {
			return ErrRuleNumberOrder
		}
		m.number = num
	}
	m.link(m.pendingNumbers[m.number])
	delete(m.pendingNumbers, m.number)
	rule := m.Rule
	rule.Record, rule.Action = *rec, rec.Instruction.Action
	switch rule.Action.Kind {
	case ipfw.ActionPass, ipfw.ActionDeny, ipfw.ActionCount, ipfw.ActionCheckState:
	case ipfw.ActionSkipTo:
		rule.Jump = len(m.ops) + 1
		switch target := rule.Action.SkipTo; target.Kind {
		case ipfw.SkipToNumber:
			m.pendingNumbers[target.Number] = append(m.pendingNumbers[target.Number], len(m.ops))
		case ipfw.SkipToLabel:
			m.pendingLabels[target.Label] = append(m.pendingLabels[target.Label], len(m.ops))
		case ipfw.SkipToTableArg:
		default:
			return ErrUnsupportedAction
		}
	default:
		return ErrUnsupportedAction
	}
	m.ops = append(m.ops, rule)
	m.number++
	m.Rule = op[V4, V6]{}
	return nil
}

// Label records the label as standing for the next rule and links the
// jumps waiting for it.
func (m *builder[V4, V6]) Label(name string) {
	m.labels[name] = len(m.ops)
	m.link(m.pendingLabels[name])
	delete(m.pendingLabels, name)
}

// Table adds the entry of a table command to the registry, a create
// command adding nothing, an interface value losing its leading colon.
//
// Network text the parser rejects is the error kind of its family.
func (m *builder[V4, V6]) Table(table *ipfw.Table) error {
	if table.Kind != ipfw.TableAdd {
		return nil
	}
	switch table.Key.Kind {
	case ipfw.TableKeyNetwork4:
		network, err := m.networks.ParseNetwork4(table.Key.Text)
		if err != nil {
			return ipfw.ErrExpectedIPv4Network
		}
		m.tables.AddNetwork4(table.Name, network)
	case ipfw.TableKeyNetwork6:
		network, err := m.networks.ParseNetwork6(table.Key.Text)
		if err != nil {
			return ipfw.ErrExpectedIPv6Network
		}
		m.tables.AddNetwork6(table.Name, network)
	case ipfw.TableKeyIfName:
		m.tables.AddInterface(table.Name, table.Key.Text, strings.TrimPrefix(table.Value, ":"))
	}
	return nil
}

// link points the jumps at the indexes to the next rule.
func (m *builder[V4, V6]) link(idxs []int) {
	for _, idx := range idxs {
		m.ops[idx].Jump = len(m.ops)
	}
}

// Unresolved returns the record of the first skipto still waiting for its
// rule number or label.
func (m *builder[V4, V6]) Unresolved() (ipfw.Record, bool) {
	first := -1
	for _, idxs := range m.pendingNumbers {
		first = lowest(first, idxs)
	}
	for _, idxs := range m.pendingLabels {
		first = lowest(first, idxs)
	}
	if first < 0 {
		return ipfw.Record{}, false
	}
	return m.ops[first].Record, true
}

// lowest returns the smallest of first and the indexes, first when it is
// not negative and smaller than all of them.
func lowest(first int, idxs []int) int {
	for _, idx := range idxs {
		if first < 0 || idx < first {
			first = idx
		}
	}
	return first
}

// Ops returns the rules assembled so far.
func (m *builder[V4, V6]) Ops() []op[V4, V6] {
	return m.ops
}

// Labels returns the index of the rule after each label.
func (m *builder[V4, V6]) Labels() map[string]int {
	return m.labels
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
	m.Rule.Sources = append(m.Rule.Sources, match)
	return nil
}

// OnDestinationTarget implements ipfw.VMState.
func (m *builder[V4, V6]) OnDestinationTarget(match ipfw.TargetMatch[V4, V6]) error {
	m.Rule.Destinations = append(m.Rule.Destinations, match)
	return nil
}

// OnSourcePort implements ipfw.VMState.
func (m *builder[V4, V6]) OnSourcePort(match ipfw.PortNumberMatch) error {
	m.Rule.SourcePorts = append(m.Rule.SourcePorts, match)
	return nil
}

// OnDestinationPort implements ipfw.VMState.
func (m *builder[V4, V6]) OnDestinationPort(match ipfw.PortNumberMatch) error {
	m.Rule.DestinationPorts = append(m.Rule.DestinationPorts, match)
	return nil
}

// OnOption implements ipfw.VMState, a custom option with no matcher, or an
// option of a kind the VM does not know, being ErrUnsupportedOption.
func (m *builder[V4, V6]) OnOption(opt ipfw.Opt) error {
	switch opt.Kind {
	case ipfw.OptEstablished, ipfw.OptIn, ipfw.OptOut, ipfw.OptFrag, ipfw.OptICMPTypes, ipfw.OptICMP6Types,
		ipfw.OptTCPFlags, ipfw.OptSourcePort, ipfw.OptDestinationPort, ipfw.OptProto, ipfw.OptVia,
		ipfw.OptKeepState, ipfw.OptComment, ipfw.OptDiverted, ipfw.OptAntiSpoof:
	case ipfw.OptCustom:
		if !m.custom {
			return ErrUnsupportedOption
		}
	default:
		return ErrUnsupportedOption
	}
	m.Rule.Options = append(m.Rule.Options, opt)
	return nil
}

// Tables is the registry the ruleset filled, the one configured or a
// fresh default.
func (m *VM[V4, V6]) Tables() TableRegistry[V4, V6] {
	return m.tables
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
//
// A matching skipto continues at its linked rule, a skipto tablearg at
// the rule the table lookup of its options named, every jump going
// forward: a tablearg with no target, or one at or before the rule,
// falls through.
func (m *VM[V4, V6]) CheckTrace(ctx *Context, pkt Packet, tracer Tracer) (ipfw.Action, bool) {
	pc := 0
	for pc < len(m.ops) {
		rule := &m.ops[pc]
		matched, target := m.matches(rule, ctx, pkt)
		tracer.Trace(&rule.Record, rule.Action, matched)
		if !matched {
			pc++
			continue
		}
		switch rule.Action.Kind {
		case ipfw.ActionPass, ipfw.ActionDeny:
			return rule.Action, true
		case ipfw.ActionSkipTo:
			if rule.Action.SkipTo.Kind == ipfw.SkipToTableArg {
				pc = max(target, pc+1)
			} else {
				pc = rule.Jump
			}
		default:
			pc++
		}
	}
	return ipfw.Action{}, false
}

// nopTracer is the tracer of Check.
type nopTracer struct{}

// Trace implements Tracer.
func (nopTracer) Trace(*ipfw.Record, ipfw.Action, bool) {}

// matches reports whether the packet satisfies the body of the rule and
// then its options, and the tablearg target the options yield.
//
// The target is the index of the rule a table lookup among the options
// named, noTarget when none did.
func (m *VM[V4, V6]) matches(rule *op[V4, V6], ctx *Context, pkt Packet) (bool, int) {
	if !matchIPProtos(rule.IPProtos, pkt.Version()) {
		return false, noTarget
	}
	if !matchProtos(rule.Protos, pkt.Protocol()) {
		return false, noTarget
	}
	if !m.matchTargets(rule.Sources, ctx, pkt.SourceAddr()) {
		return false, noTarget
	}
	if !m.matchTargets(rule.Destinations, ctx, pkt.DestinationAddr()) {
		return false, noTarget
	}
	if len(rule.SourcePorts) > 0 {
		port, ok := pkt.SourcePort()
		if !ok || !matchPorts(rule.SourcePorts, port) {
			return false, noTarget
		}
	}
	if len(rule.DestinationPorts) > 0 {
		port, ok := pkt.DestinationPort()
		if !ok || !matchPorts(rule.DestinationPorts, port) {
			return false, noTarget
		}
	}
	return m.matchOptions(rule.Options, ctx, pkt)
}

// matchPorts reports whether the port is in one of the ranges, or, the
// list being negated, in none of them.
//
// One `not` negates a whole list, so every element carries the same flag.
func matchPorts(matches []ipfw.PortNumberMatch, port uint16) bool {
	for _, match := range matches {
		if match.Lo <= port && port <= match.Hi {
			return !match.Neg
		}
	}
	return len(matches) > 0 && matches[0].Neg
}

// noTarget is the tablearg target of a rule whose options named none.
const noTarget = -1

// matchOptions folds the options left to right: an option starting a
// term must find the previous term true, one marked Or extends the term.
//
// The target is the first one an option yields.
func (m *VM[V4, V6]) matchOptions(options []ipfw.Opt, ctx *Context, pkt Packet) (bool, int) {
	term, target := true, noTarget
	for idx := range options {
		opt := &options[idx]
		raw, found := m.matchOption(opt, ctx, pkt)
		if target == noTarget {
			target = found
		}
		hit := raw != opt.Neg
		if opt.Or {
			term = term || hit
			continue
		}
		if !term {
			return false, noTarget
		}
		term = hit
	}
	return term, target
}

// matchOption reports whether the option, its negation aside, holds for
// the packet in the context, and the tablearg target it yields.
//
// established is a TCP packet with ACK or RST set, tcpflags one whose
// examined flags are exactly the ones to be set, src-port and dst-port a
// packet whose port is in the range, proto one of the protocol number, in
// and out the direction of the check, via the context's interface by
// name, by mask or through a table, frag a non-first fragment, icmptypes
// and icmp6types an ICMP packet of the family with a type in the set.
// The options the VM does not emulate follow matchPolicy, a custom one
// the configured matcher.
func (m *VM[V4, V6]) matchOption(opt *ipfw.Opt, ctx *Context, pkt Packet) (bool, int) {
	switch opt.Kind {
	case ipfw.OptKeepState, ipfw.OptComment, ipfw.OptDiverted, ipfw.OptAntiSpoof:
		return matchPolicy(opt.Kind, ctx), noTarget
	case ipfw.OptCustom:
		return m.matcher(*opt, ctx, pkt), noTarget
	case ipfw.OptEstablished:
		flags, ok := pkt.TCPFlags()
		return ok && flags&(ipfw.TCPAck|ipfw.TCPRst) != 0, noTarget
	case ipfw.OptTCPFlags:
		flags, ok := pkt.TCPFlags()
		return ok && flags&opt.TCPFlags.Mask == opt.TCPFlags.Set, noTarget
	case ipfw.OptSourcePort:
		port, ok := pkt.SourcePort()
		return ok && opt.Ports.Lo.Number <= port && port <= opt.Ports.Hi.Number, noTarget
	case ipfw.OptDestinationPort:
		port, ok := pkt.DestinationPort()
		return ok && opt.Ports.Lo.Number <= port && port <= opt.Ports.Hi.Number, noTarget
	case ipfw.OptProto:
		return pkt.Protocol() == opt.Proto.Number, noTarget
	case ipfw.OptIn:
		return ctx.Direction == In, noTarget
	case ipfw.OptOut:
		return ctx.Direction == Out, noTarget
	case ipfw.OptVia:
		return m.matchVia(&opt.Via, ctx)
	case ipfw.OptFrag:
		return pkt.IsFragment(), noTarget
	case ipfw.OptICMPTypes:
		ty, ok := pkt.ICMPType()
		return ok && opt.Types.Has(ty), noTarget
	case ipfw.OptICMP6Types:
		ty, ok := pkt.ICMP6Type()
		return ok && opt.Types.Has(ty), noTarget
	}
	return false, noTarget
}

// matchPolicy is the fixed verdict of an option whose meaning the VM
// cannot reproduce.
//
// keep-state holds, the VM being stateless and the state it would create
// of no consequence to the verdict. A comment holds, being no condition.
// diverted never holds, there being no divert sockets. antispoof holds
// on the way out and never on the way in, the VM knowing no topology to
// tell a spoofed source by.
func matchPolicy(kind ipfw.OptKind, ctx *Context) bool {
	switch kind {
	case ipfw.OptKeepState, ipfw.OptComment:
		return true
	case ipfw.OptAntiSpoof:
		return ctx.Direction == Out
	}
	return false
}

// matchVia reports whether the context's interface is the one named, one
// the mask takes or one the table lists, and the target of the table entry.
//
// A mask like `*` takes even no interface at all. The value of a table
// entry names the label a tablearg jumps to, the target being the rule
// after it, or none when no label is so named. The value written in the
// option is not consulted.
func (m *VM[V4, V6]) matchVia(via *ipfw.Via, ctx *Context) (bool, int) {
	switch via.Kind {
	case ipfw.ViaExact:
		return ctx.IfName == via.Name, noTarget
	case ipfw.ViaMask:
		return ipfw.MatchIfMask(via.Name, ctx.IfName), noTarget
	case ipfw.ViaTable:
		value, ok := m.tables.LookupInterface(via.Name, ctx.IfName)
		if !ok {
			return false, noTarget
		}
		if target, ok := m.labels[value]; ok {
			return true, target
		}
		return true, noTarget
	}
	return false, noTarget
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
// The networks a name stands for, the ones marked Or after the first,
// are one target: the address is in any of them, or in none when the
// name is negated. A side left empty by a name standing for nothing is
// a rule that never matches.
func (m *VM[V4, V6]) matchTargets(targets []ipfw.TargetMatch[V4, V6], ctx *Context, addr netip.Addr) bool {
	idx := 0
	for idx < len(targets) {
		first := targets[idx]
		hit := m.matchTarget(first, ctx, addr)
		for idx++; idx < len(targets) && targets[idx].Or; idx++ {
			hit = hit || m.matchTarget(targets[idx], ctx, addr)
		}
		if hit != first.Neg {
			return true
		}
	}
	return false
}

// matchTarget reports whether the address is the target's.
//
// me and me6 are the context's addresses of the packet's family, a
// missing table holds nothing.
func (m *VM[V4, V6]) matchTarget(target ipfw.TargetMatch[V4, V6], ctx *Context, addr netip.Addr) bool {
	switch target.Kind {
	case ipfw.TargetAny:
		return true
	case ipfw.TargetMe:
		return addr.Is4() && slices.Contains(ctx.LocalAddrs, addr)
	case ipfw.TargetMe6:
		return addr.Is6() && slices.Contains(ctx.LocalAddrs, addr)
	case ipfw.TargetTable:
		return m.tables.LookupNetwork(target.Name, addr)
	case ipfw.TargetNetwork4:
		return addr.Is4() && target.Net4.ContainsAddr(addr)
	case ipfw.TargetNetwork6:
		return addr.Is6() && target.Net6.ContainsAddr(addr)
	}
	return false
}
