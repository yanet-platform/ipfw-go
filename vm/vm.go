package vm

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/yanet-platform/ipfw-go"
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

// Config is what a VM is built with beyond the ruleset, every part but
// the environment's network parser optional.
type Config[V4, V6 any] struct {
	// Environment is what the names of the ruleset are interpreted in.
	Environment ipfw.Environment[V4, V6]
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
	program program[V4, V6]
	labels  map[string]int
	tables  TableRegistry[V4, V6]
	matcher OptionMatcher
	verdict ipfw.Action
}

// program is the rules of a VM laid out for the scan of a check.
//
// What a rule is matched by takes one cache line, the tokens of every
// rule sit in one arena per kind, a rule's tokens being a run of each,
// and the records and the actions stay aside, so a scan reads memory in
// order and a build allocates per arena rather than per rule. The
// callbacks append to the arenas, Mark and Close delimit a rule's runs.
type program[V4, V6 Network] struct {
	rules            []rule
	records          []ipfw.Record
	actions          []ipfw.Action
	ipProtos         []ipfw.ProtoIPMatch
	protos           []ipfw.ProtoNumberMatch
	sources          []ipfw.TargetMatch[V4, V6]
	destinations     []ipfw.TargetMatch[V4, V6]
	sourcePorts      []ipfw.PortNumberMatch
	destinationPorts []ipfw.PortNumberMatch
	options          []ipfw.Opt
}

// Len is the number of rules.
func (m *program[V4, V6]) Len() int {
	return len(m.rules)
}

// Rules returns the rules in order.
func (m *program[V4, V6]) Rules() []rule {
	return m.rules
}

// Record returns the line the rule came from.
func (m *program[V4, V6]) Record(idx int) *ipfw.Record {
	return &m.records[idx]
}

// Action returns what a match of the rule does.
func (m *program[V4, V6]) Action(idx int) ipfw.Action {
	return m.actions[idx]
}

// Append adds a rule closed over the arenas with the record it came from.
func (m *program[V4, V6]) Append(closed rule, rec *ipfw.Record) {
	m.rules = append(m.rules, closed)
	m.records = append(m.records, *rec)
	m.actions = append(m.actions, rec.Instruction.Action)
}

// Link points the jump of the rule at the target.
func (m *program[V4, V6]) Link(idx, target int) {
	m.rules[idx].Jump = uint32(target)
}

// Mark returns a rule whose runs all start, empty, where the arenas end.
func (m *program[V4, V6]) Mark() rule {
	at := func(n int) span {
		return span{Start: uint32(n), End: uint32(n)}
	}
	return rule{
		IPProtos:         at(len(m.ipProtos)),
		Protos:           at(len(m.protos)),
		Sources:          at(len(m.sources)),
		Destinations:     at(len(m.destinations)),
		SourcePorts:      at(len(m.sourcePorts)),
		DestinationPorts: at(len(m.destinationPorts)),
		Options:          at(len(m.options)),
	}
}

// Close ends every run of the rule where the arenas end now.
func (m *program[V4, V6]) Close(open rule) rule {
	open.IPProtos.End = uint32(len(m.ipProtos))
	open.Protos.End = uint32(len(m.protos))
	open.Sources.End = uint32(len(m.sources))
	open.Destinations.End = uint32(len(m.destinations))
	open.SourcePorts.End = uint32(len(m.sourcePorts))
	open.DestinationPorts.End = uint32(len(m.destinationPorts))
	open.Options.End = uint32(len(m.options))
	return open
}

// OnIPProto implements ipfw.VMState.
func (m *program[V4, V6]) OnIPProto(match ipfw.ProtoIPMatch) error {
	m.ipProtos = append(m.ipProtos, match)
	return nil
}

// OnProto implements ipfw.VMState.
func (m *program[V4, V6]) OnProto(match ipfw.ProtoNumberMatch) error {
	m.protos = append(m.protos, match)
	return nil
}

// OnSourceTarget implements ipfw.VMState.
func (m *program[V4, V6]) OnSourceTarget(match ipfw.TargetMatch[V4, V6]) error {
	m.sources = append(m.sources, match)
	return nil
}

// OnDestinationTarget implements ipfw.VMState.
func (m *program[V4, V6]) OnDestinationTarget(match ipfw.TargetMatch[V4, V6]) error {
	m.destinations = append(m.destinations, match)
	return nil
}

// OnSourcePort implements ipfw.VMState.
func (m *program[V4, V6]) OnSourcePort(match ipfw.PortNumberMatch) error {
	m.sourcePorts = append(m.sourcePorts, match)
	return nil
}

// OnDestinationPort implements ipfw.VMState.
func (m *program[V4, V6]) OnDestinationPort(match ipfw.PortNumberMatch) error {
	m.destinationPorts = append(m.destinationPorts, match)
	return nil
}

// OnOption implements ipfw.VMState.
func (m *program[V4, V6]) OnOption(opt ipfw.Opt) error {
	m.options = append(m.options, opt)
	return nil
}

// The runs of the arenas, one accessor each so that the scan inlines them.

// IPProtos returns the run of the IP version sets.
func (m *program[V4, V6]) IPProtos(at span) []ipfw.ProtoIPMatch {
	return m.ipProtos[at.Start:at.End]
}

// Protos returns the run of the transport protocols.
func (m *program[V4, V6]) Protos(at span) []ipfw.ProtoNumberMatch {
	return m.protos[at.Start:at.End]
}

// Sources returns the run of the source targets.
func (m *program[V4, V6]) Sources(at span) []ipfw.TargetMatch[V4, V6] {
	return m.sources[at.Start:at.End]
}

// Destinations returns the run of the destination targets.
func (m *program[V4, V6]) Destinations(at span) []ipfw.TargetMatch[V4, V6] {
	return m.destinations[at.Start:at.End]
}

// SourcePorts returns the run of the source port ranges.
func (m *program[V4, V6]) SourcePorts(at span) []ipfw.PortNumberMatch {
	return m.sourcePorts[at.Start:at.End]
}

// DestinationPorts returns the run of the destination port ranges.
func (m *program[V4, V6]) DestinationPorts(at span) []ipfw.PortNumberMatch {
	return m.destinationPorts[at.Start:at.End]
}

// Options returns the run of the options.
func (m *program[V4, V6]) Options(at span) []ipfw.Opt {
	return m.options[at.Start:at.End]
}

// rule is what a check matches a packet by and where a match goes, one
// cache line.
//
// An empty run of IP versions, protocols or ports means any, an empty run
// of targets nothing.
type rule struct {
	// Kind is the action kind, what a match does.
	Kind ipfw.ActionKind
	// TableArg is whether a skipto takes its target from the options.
	TableArg bool
	// Jump is the index of the rule a matching skipto continues at, always
	// past this one: the next rule until the jump is linked.
	Jump uint32
	// IPProtos is the run of the IP version sets.
	IPProtos span
	// Protos is the run of the transport protocols.
	Protos span
	// Sources is the run of the source targets.
	Sources span
	// Destinations is the run of the destination targets.
	Destinations span
	// SourcePorts is the run of the source port ranges.
	SourcePorts span
	// DestinationPorts is the run of the destination port ranges.
	DestinationPorts span
	// Options is the run of the options.
	Options span
}

// span is a run of an arena.
type span struct {
	// Start is the index of the first element.
	Start uint32
	// End is the index after the last element.
	End uint32
}

// Empty reports whether the run holds nothing.
func (m span) Empty() bool {
	return m.End == m.Start
}

// Build reads the whole ruleset from p into a VM, every name resolved
// within the configured environment on the way in.
func Build[V4, V6 Network](p *ipfw.Parser, cfg Config[V4, V6]) (*VM[V4, V6], error) {
	tables, verdict := cfg.Tables, cfg.DefaultVerdict
	if tables == nil {
		tables = NewDefaultTableRegistry[V4, V6]()
	}
	if verdict.Kind == 0 {
		verdict = ipfw.Action{Kind: ipfw.ActionDeny}
	}
	sink := newBuilder(tables, cfg.Environment.Networks, cfg.OptionMatcher != nil)
	state := ipfw.NewResolver(sink, cfg.Environment)
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
			return &VM[V4, V6]{
				program: sink.Program(),
				labels:  sink.Labels(),
				tables:  tables,
				matcher: cfg.OptionMatcher,
				verdict: verdict,
			}, nil
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
// the program.
//
// The program it embeds takes the tokens of the rule under construction,
// the builder rejecting the options the VM does not take, which the parser
// then positions at the token. Add closes the rule over them, numbering it
// and linking the jumps, Label links the jumps to a label, Table fills the
// registry.
type builder[V4, V6 Network] struct {
	program[V4, V6]
	// start is the rule under construction, its runs open where the arenas
	// stood when it began.
	start    rule
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

// Program returns the program assembled so far.
func (m *builder[V4, V6]) Program() program[V4, V6] {
	return m.program
}

// Add closes the rule of the instruction just read over the tokens
// appended for it and starts the next one.
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
	idx := m.Len()
	closed := m.Close(m.start)
	closed.Kind = rec.Instruction.Action.Kind
	switch closed.Kind {
	case ipfw.ActionPass, ipfw.ActionDeny, ipfw.ActionCount, ipfw.ActionCheckState:
	case ipfw.ActionSkipTo:
		closed.Jump = uint32(idx + 1)
		switch target := rec.Instruction.Action.SkipTo; target.Kind {
		case ipfw.SkipToNumber:
			m.pendingNumbers[target.Number] = append(m.pendingNumbers[target.Number], idx)
		case ipfw.SkipToLabel:
			m.pendingLabels[target.Label] = append(m.pendingLabels[target.Label], idx)
		case ipfw.SkipToTableArg:
			closed.TableArg = true
		default:
			return ErrUnsupportedAction
		}
	default:
		return ErrUnsupportedAction
	}
	m.Append(closed, rec)
	m.number++
	m.start = m.Mark()
	return nil
}

// Label records the label as standing for the next rule and links the
// jumps waiting for it.
func (m *builder[V4, V6]) Label(name string) {
	m.labels[name] = m.Len()
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
		m.Link(idx, m.Len())
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
	return *m.Record(first), true
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

// Labels returns the index of the rule after each label.
func (m *builder[V4, V6]) Labels() map[string]int {
	return m.labels
}

// OnOption implements ipfw.VMState, a custom option with no matcher, or an
// option of a kind the VM does not know, being ErrUnsupportedOption.
func (m *builder[V4, V6]) OnOption(opt ipfw.Opt) error {
	switch opt.Kind {
	case ipfw.OptEstablished, ipfw.OptIn, ipfw.OptOut, ipfw.OptFrag, ipfw.OptICMPTypes,
		ipfw.OptICMP6Types, ipfw.OptTCPFlags, ipfw.OptSourcePort, ipfw.OptDestinationPort,
		ipfw.OptProto, ipfw.OptVia, ipfw.OptKeepState, ipfw.OptComment, ipfw.OptDiverted,
		ipfw.OptAntiSpoof:
	case ipfw.OptCustom:
		if !m.custom {
			return ErrUnsupportedOption
		}
	default:
		return ErrUnsupportedOption
	}
	return m.program.OnOption(opt)
}

// Tables is the registry the ruleset filled, the one configured or a
// fresh default.
func (m *VM[V4, V6]) Tables() TableRegistry[V4, V6] {
	return m.tables
}

// Len is the number of rules.
func (m *VM[V4, V6]) Len() int {
	return m.program.Len()
}

// Check runs the packet through the rules and returns the verdict, the
// default one when no rule terminates the search.
func (m *VM[V4, V6]) Check(ctx *Context, pkt Packet) ipfw.Action {
	if action, matched := m.CheckTrace(ctx, pkt, nil); matched {
		return action
	}
	return m.verdict
}

// CheckTrace is Check reporting every rule evaluated to tracer, nil
// reporting nothing, and whether a rule terminated the search.
//
// A matching skipto continues at its linked rule, a skipto tablearg at
// the rule the table lookup of its options named, every jump going
// forward: a tablearg with no target, or one at or before the rule,
// falls through.
func (m *VM[V4, V6]) CheckTrace(ctx *Context, pkt Packet, tracer Tracer) (ipfw.Action, bool) {
	fields := readFields(pkt)
	program := &m.program
	rules := program.Rules()
	pc := 0
	for pc < len(rules) {
		rule := &rules[pc]
		matched, target := m.matches(rule, ctx, pkt, &fields)
		if tracer != nil {
			tracer.Trace(program.Record(pc), program.Action(pc), matched)
		}
		if !matched {
			pc++
			continue
		}
		switch rule.Kind {
		case ipfw.ActionPass, ipfw.ActionDeny:
			return program.Action(pc), true
		case ipfw.ActionSkipTo:
			if rule.TableArg {
				pc = max(target, pc+1)
			} else {
				pc = int(rule.Jump)
			}
		default:
			pc++
		}
	}
	return ipfw.Action{}, false
}

// packetFields is what the matchers read from a packet, taken once per
// check: what every rule needs up front, the rest on first use.
//
// Reading them through the Packet interface at every rule cost a dynamic
// call and an address conversion each, most of the time of a rule that
// does not match.
type packetFields struct {
	// Version is the IP version.
	Version IPVersion
	// Protocol is the transport protocol number.
	Protocol uint8
	// Source is the source address.
	Source netip.Addr
	// Destination is the destination address.
	Destination netip.Addr
	// SourcePort is the source port, after ReadPorts.
	SourcePort uint16
	// HasSourcePort is whether the packet carries a source port.
	HasSourcePort bool
	// DestinationPort is the destination port, after ReadPorts.
	DestinationPort uint16
	// HasDestinationPort is whether the packet carries a destination port.
	HasDestinationPort bool
	// Flags are the TCP flags, after ReadFlags.
	Flags ipfw.TCPFlag
	// HasFlags is whether the packet carries TCP flags.
	HasFlags bool
	// ICMPType is the ICMP type, after ReadICMP.
	ICMPType uint8
	// HasICMPType is whether the packet is ICMP.
	HasICMPType bool
	// ICMP6Type is the ICMPv6 type, after ReadICMP.
	ICMP6Type uint8
	// HasICMP6Type is whether the packet is ICMPv6.
	HasICMP6Type bool
	// Fragment is whether the packet is a non-first fragment, after
	// ReadFragment.
	Fragment bool

	ports, tcp, icmp, fragmentation bool
}

// readFields takes the fields every rule looks at from the packet.
func readFields(pkt Packet) packetFields {
	return packetFields{
		Version:     pkt.Version(),
		Protocol:    pkt.Protocol(),
		Source:      pkt.SourceAddr(),
		Destination: pkt.DestinationAddr(),
	}
}

// ReadPorts takes the ports on first use.
func (m *packetFields) ReadPorts(pkt Packet) {
	if !m.ports {
		m.SourcePort, m.HasSourcePort = pkt.SourcePort()
		m.DestinationPort, m.HasDestinationPort = pkt.DestinationPort()
		m.ports = true
	}
}

// ReadFlags takes the TCP flags on first use.
func (m *packetFields) ReadFlags(pkt Packet) {
	if !m.tcp {
		m.Flags, m.HasFlags = pkt.TCPFlags()
		m.tcp = true
	}
}

// ReadICMP takes the ICMP and ICMPv6 types on first use.
func (m *packetFields) ReadICMP(pkt Packet) {
	if !m.icmp {
		m.ICMPType, m.HasICMPType = pkt.ICMPType()
		m.ICMP6Type, m.HasICMP6Type = pkt.ICMP6Type()
		m.icmp = true
	}
}

// ReadFragment takes whether the packet is a fragment on first use.
func (m *packetFields) ReadFragment(pkt Packet) {
	if !m.fragmentation {
		m.Fragment = pkt.IsFragment()
		m.fragmentation = true
	}
}

// matches reports whether the packet satisfies the body of the rule and
// then its options, and the tablearg target the options yield.
//
// The target is the index of the rule a table lookup among the options
// named, noTarget when none did.
func (m *VM[V4, V6]) matches(
	rule *rule,
	ctx *Context,
	pkt Packet,
	fields *packetFields,
) (bool, int) {
	program := &m.program
	if !rule.IPProtos.Empty() && !matchIPProtos(program.IPProtos(rule.IPProtos), fields.Version) {
		return false, noTarget
	}
	if !rule.Protos.Empty() && !matchProtos(program.Protos(rule.Protos), fields.Protocol) {
		return false, noTarget
	}
	if !m.matchTargets(program.Sources(rule.Sources), ctx, fields.Source) {
		return false, noTarget
	}
	if !m.matchTargets(program.Destinations(rule.Destinations), ctx, fields.Destination) {
		return false, noTarget
	}
	if !rule.SourcePorts.Empty() {
		fields.ReadPorts(pkt)
		ports := program.SourcePorts(rule.SourcePorts)
		if !fields.HasSourcePort || !matchPorts(ports, fields.SourcePort) {
			return false, noTarget
		}
	}
	if !rule.DestinationPorts.Empty() {
		fields.ReadPorts(pkt)
		ports := program.DestinationPorts(rule.DestinationPorts)
		if !fields.HasDestinationPort || !matchPorts(ports, fields.DestinationPort) {
			return false, noTarget
		}
	}
	if rule.Options.Empty() {
		return true, noTarget
	}
	return m.matchOptions(program.Options(rule.Options), ctx, pkt, fields)
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
func (m *VM[V4, V6]) matchOptions(
	options []ipfw.Opt,
	ctx *Context,
	pkt Packet,
	fields *packetFields,
) (bool, int) {
	term, target := true, noTarget
	for idx := range options {
		opt := &options[idx]
		raw, found := m.matchOption(opt, ctx, pkt, fields)
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
// the configured matcher, which sees the packet itself.
func (m *VM[V4, V6]) matchOption(
	opt *ipfw.Opt,
	ctx *Context,
	pkt Packet,
	fields *packetFields,
) (bool, int) {
	switch opt.Kind {
	case ipfw.OptKeepState, ipfw.OptComment, ipfw.OptDiverted, ipfw.OptAntiSpoof:
		return matchPolicy(opt.Kind, ctx), noTarget
	case ipfw.OptCustom:
		return m.matcher(*opt, ctx, pkt), noTarget
	case ipfw.OptEstablished:
		fields.ReadFlags(pkt)
		return fields.HasFlags && fields.Flags&(ipfw.TCPAck|ipfw.TCPRst) != 0, noTarget
	case ipfw.OptTCPFlags:
		fields.ReadFlags(pkt)
		return fields.HasFlags && fields.Flags&opt.TCPFlags.Mask == opt.TCPFlags.Set, noTarget
	case ipfw.OptSourcePort:
		fields.ReadPorts(pkt)
		return fields.HasSourcePort && inRange(fields.SourcePort, opt.Ports), noTarget
	case ipfw.OptDestinationPort:
		fields.ReadPorts(pkt)
		return fields.HasDestinationPort && inRange(fields.DestinationPort, opt.Ports), noTarget
	case ipfw.OptProto:
		return fields.Protocol == opt.Proto.Number, noTarget
	case ipfw.OptIn:
		return ctx.Direction == In, noTarget
	case ipfw.OptOut:
		return ctx.Direction == Out, noTarget
	case ipfw.OptVia:
		return m.matchVia(&opt.Via, ctx)
	case ipfw.OptFrag:
		fields.ReadFragment(pkt)
		return fields.Fragment, noTarget
	case ipfw.OptICMPTypes:
		fields.ReadICMP(pkt)
		return fields.HasICMPType && opt.Types.Has(fields.ICMPType), noTarget
	case ipfw.OptICMP6Types:
		fields.ReadICMP(pkt)
		return fields.HasICMP6Type && opt.Types.Has(fields.ICMP6Type), noTarget
	}
	return false, noTarget
}

// inRange reports whether the port is within the range of an option.
func inRange(port uint16, ports ipfw.PortRange) bool {
	return ports.Lo.Number <= port && port <= ports.Hi.Number
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
// The consecutive targets of one pattern are alternatives: the address is in
// any of them, or in none when the pattern is negated. A side left empty by a
// name standing for nothing is a rule that never matches.
func (m *VM[V4, V6]) matchTargets(
	targets []ipfw.TargetMatch[V4, V6],
	ctx *Context,
	addr netip.Addr,
) bool {
	idx := 0
	for idx < len(targets) {
		first := targets[idx]
		hit := m.matchTarget(first, ctx, addr)
		for idx++; idx < len(targets) && targets[idx].Pattern == first.Pattern; idx++ {
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
func (m *VM[V4, V6]) matchTarget(
	target ipfw.TargetMatch[V4, V6],
	ctx *Context,
	addr netip.Addr,
) bool {
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
