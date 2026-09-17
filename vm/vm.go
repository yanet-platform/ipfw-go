package vm

import (
	"cmp"
	"errors"
	"math"
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
	// NumHostBits returns the number of host bits, the zero bits of the
	// mask, fewer making a network more specific in a table.
	NumHostBits() int
}

// TableRegistry holds the tables of a ruleset, filled while building and
// consulted while matching.
type TableRegistry[V4, V6 any] interface {
	// LookupNetwork reports the value of the table's entry holding addr, the
	// most specific one when several do, as ipfw(8) looks up a prefix, false
	// when none does or the table does not exist.
	LookupNetwork(table string, addr netip.Addr) (string, bool)
	// LookupInterface reports the value of an interface in the table.
	LookupInterface(table, ifname string) (string, bool)
	// AddNetwork4 adds an IPv4 network with its value to the table.
	AddNetwork4(table string, network V4, value string)
	// AddNetwork6 adds an IPv6 network with its value to the table.
	AddNetwork6(table string, network V6, value string)
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
	// ErrUnsupportedTableType is a create of a table type the VM cannot hold.
	ErrUnsupportedTableType = errors.New("unsupported table type")
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
	numbers          []uint32
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

// Append adds a rule closed over the arenas with its number and the record
// it came from.
func (m *program[V4, V6]) Append(closed rule, number uint32, rec *ipfw.Record) {
	m.rules = append(m.rules, closed)
	m.numbers = append(m.numbers, number)
	m.records = append(m.records, *rec)
	m.actions = append(m.actions, rec.Instruction.Action)
}

// Number returns the number of the rule.
func (m *program[V4, V6]) Number(idx int) uint32 {
	return m.numbers[idx]
}

// At returns the index of the first rule numbered at or after number, the
// number of rules when none is, the rule numbers going up.
func (m *program[V4, V6]) At(number uint64) int {
	idx, _ := slices.BinarySearchFunc(m.numbers, number, func(have uint32, want uint64) int {
		return cmp.Compare(uint64(have), want)
	})
	return idx
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

// DropComments removes the comments that decide nothing from the options of
// the rule, so that a commented rule keeps an empty run of options.
//
// A comment holds for every packet, so dropping it changes no verdict unless
// it is negated or shares its or-block with another option. The options of a
// block are contiguous, so a neighbour tells.
func (m *program[V4, V6]) DropComments(open rule) {
	options := m.options[open.Options.Start:]
	kept := 0
	for idx, opt := range options {
		alone := (idx == 0 || options[idx-1].Block != opt.Block) &&
			(idx+1 == len(options) || options[idx+1].Block != opt.Block)
		if opt.Kind == ipfw.OptComment && !opt.Neg && alone {
			continue
		}
		options[kept] = opt
		kept++
	}
	m.options = m.options[:int(open.Options.Start)+kept]
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
//
// The parser chooses the grammar of every rule body, so the ipfw(8) choice by
// the first protocol needs a parser built with ipfw.WithProtoChecker.
func Build[V4, V6 Network](p *ipfw.Parser, cfg Config[V4, V6]) (*VM[V4, V6], error) {
	tables, verdict := cfg.Tables, cfg.DefaultVerdict
	if tables == nil {
		tables = NewDefaultTableRegistry[V4, V6]()
	}
	if verdict.Kind == 0 {
		verdict = ipfw.Action{Kind: ipfw.ActionDeny}
	}
	sink := newBuilder(tables, cfg.Environment, cfg.OptionMatcher != nil)
	state := ipfw.NewResolver(sink, cfg.Environment)
	for {
		rec, parseErr := p.Next(state)
		if parseErr != nil {
			return nil, &BuildError{Line: parseErr.Line, Text: parseErr.Text, Err: parseErr}
		}
		switch rec.Kind {
		case ipfw.RecordEOF:
			sink.LinkNumbers()
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
	targets  ipfw.TargetResolver[V4, V6]
	// tableTypes is the type each created table was given, a table absent
	// from it being an address table.
	tableTypes map[string]ipfw.TableType
	// custom is whether a custom option has a matcher to go to.
	custom bool
	// number is the rule number the next instruction gets, one past the
	// previous rule unless the instruction gives its own, which may only
	// move it forward.
	number uint32
	// labels is the index of the rule after each label, the last
	// occurrence winning.
	labels map[string]int
	// numberJumps holds the indexes of the skipto rules to a number, linked
	// once every rule number is known, and unresolvedNumbers those no later
	// rule is numbered for.
	numberJumps       []int
	unresolvedNumbers []int
	// pendingLabels holds, by label, the indexes of the skipto rules waiting
	// for it.
	pendingLabels map[string][]int
}

func newBuilder[V4, V6 Network](
	tables TableRegistry[V4, V6],
	env ipfw.Environment[V4, V6],
	custom bool,
) *builder[V4, V6] {
	return &builder[V4, V6]{
		tables:        tables,
		networks:      env.Networks,
		targets:       env.Targets,
		tableTypes:    map[string]ipfw.TableType{},
		custom:        custom,
		number:        1,
		labels:        map[string]int{},
		pendingLabels: map[string][]int{},
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
// the next rule until LinkNumbers or a later label links the jump, so every
// jump goes forward.
func (m *builder[V4, V6]) Add(rec *ipfw.Record) error {
	if num := rec.Instruction.Num; num != 0 {
		if num < m.number {
			return ErrRuleNumberOrder
		}
		m.number = num
	}
	idx := m.Len()
	if idx > 0 && m.number <= m.Number(idx-1) {
		// The numbering wrapped past the largest rule number.
		return ErrRuleNumberOrder
	}
	m.DropComments(m.start)
	closed := m.Close(m.start)
	closed.Kind = rec.Instruction.Action.Kind
	switch closed.Kind {
	case ipfw.ActionPass, ipfw.ActionDeny, ipfw.ActionCount, ipfw.ActionCheckState:
	case ipfw.ActionSkipTo:
		closed.Jump = uint32(idx + 1)
		switch target := rec.Instruction.Action.SkipTo; target.Kind {
		case ipfw.SkipToNumber:
			m.numberJumps = append(m.numberJumps, idx)
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
	m.Append(closed, m.number, rec)
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

// Table records the type of a created table or adds the entry of an add to
// the registry, its value losing a leading colon.
//
// A table never created is an address table, as ipfw(8) makes it. An
// address table takes network text through the network parser and any
// other key through the target resolver, a name standing for nothing
// adding nothing and no resolver being ErrUnresolvedTarget. An interface
// table takes every key as an interface name. A type the VM cannot hold
// is ErrUnsupportedTableType at its create.
func (m *builder[V4, V6]) Table(table *ipfw.Table) error {
	switch table.Kind {
	case ipfw.TableCreate:
		return m.createTable(table)
	case ipfw.TableAdd:
		value := strings.TrimPrefix(table.Value, ":")
		if m.tableTypes[table.Name] == ipfw.TableTypeIface {
			m.tables.AddInterface(table.Name, table.Key.Text, value)
			return nil
		}
		return m.addAddress(table, value)
	}
	return nil
}

// createTable records the type of the table, an omitted one being addr.
func (m *builder[V4, V6]) createTable(table *ipfw.Table) error {
	switch table.Type {
	case ipfw.TableTypeUnset, ipfw.TableTypeAddr:
		m.tableTypes[table.Name] = ipfw.TableTypeAddr
	case ipfw.TableTypeIface:
		m.tableTypes[table.Name] = ipfw.TableTypeIface
	default:
		return ErrUnsupportedTableType
	}
	return nil
}

// addAddress adds the key of an address table with the value, network text
// through the network parser and a name through the target resolver, every
// network it stands for taking the value.
//
// Network text the parser rejects is the error kind of its family, the
// resolver's error comes back as is.
func (m *builder[V4, V6]) addAddress(table *ipfw.Table, value string) error {
	target := ipfw.Target{Kind: ipfw.TargetCustom, Text: table.Key.Text}
	switch table.Key.Kind {
	case ipfw.TableKeyNetwork4:
		network, err := m.networks.ParseNetwork4(table.Key.Text)
		if err != nil {
			return ipfw.ErrExpectedIPv4Network
		}
		m.tables.AddNetwork4(table.Name, network, value)
		return nil
	case ipfw.TableKeyNetwork6:
		network, err := m.networks.ParseNetwork6(table.Key.Text)
		if err != nil {
			return ipfw.ErrExpectedIPv6Network
		}
		m.tables.AddNetwork6(table.Name, network, value)
		return nil
	case ipfw.TableKeyHostname:
		target.Kind = ipfw.TargetHostname
	}
	if m.targets == nil {
		return ipfw.ErrUnresolvedTarget
	}
	nets4, nets6, err := m.targets.ResolveTarget(target)
	if err != nil {
		return err
	}
	for _, network := range nets4 {
		m.tables.AddNetwork4(table.Name, network, value)
	}
	for _, network := range nets6 {
		m.tables.AddNetwork6(table.Name, network, value)
	}
	return nil
}

// link points the jumps at the indexes to the next rule.
func (m *builder[V4, V6]) link(idxs []int) {
	for _, idx := range idxs {
		m.Link(idx, m.Len())
	}
}

// LinkNumbers links every skipto to a number to the first later rule
// numbered at or after it, as ipfw(8) jumps once the ruleset is complete.
//
// A target at or before the rule's own number lands on the next rule, so no
// jump goes back. A target no later rule reaches stays unresolved.
func (m *builder[V4, V6]) LinkNumbers() {
	for _, idx := range m.numberJumps {
		target := max(uint64(m.Action(idx).SkipTo.Number), uint64(m.Number(idx))+1)
		if at := m.At(target); at < m.Len() {
			m.Link(idx, at)
		} else {
			m.unresolvedNumbers = append(m.unresolvedNumbers, idx)
		}
	}
}

// Unresolved returns the record of the first skipto still waiting for its
// rule number or label, after LinkNumbers.
func (m *builder[V4, V6]) Unresolved() (ipfw.Record, bool) {
	first := lowest(-1, m.unresolvedNumbers)
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
// the rule the last table lookup of the rule that found an entry named,
// every jump going forward: a tablearg with no target, or one at or before
// the rule, falls through, and one past the last rule ends the search.
func (m *VM[V4, V6]) CheckTrace(ctx *Context, pkt Packet, tracer Tracer) (ipfw.Action, bool) {
	var fields packetFields
	fields.Read(pkt)
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
				// A lookup among the options comes after those of the
				// addresses, so theirs counts only when the options found none.
				if target == noTarget {
					target = m.addressTarget(pc, ctx, &fields)
				}
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
	// SourceFamily is the family of the source address, DestinationFamily
	// that of the destination.
	SourceFamily, DestinationFamily IPVersion
	// Source is the source address.
	Source netip.Addr
	// Destination is the destination address.
	Destination netip.Addr
	// SourcePort is the source port, after ReadPorts.
	SourcePort uint16
	// HasSourcePort is whether the packet carries a source port that means
	// something, a first fragment or whole packet of a protocol with ports.
	HasSourcePort bool
	// DestinationPort is the destination port, after ReadPorts.
	DestinationPort uint16
	// HasDestinationPort is HasSourcePort for the destination port.
	HasDestinationPort bool
	// Flags are the TCP flags, after ReadFlags.
	Flags ipfw.TCPFlag
	// HasFlags is whether the packet carries TCP flags, a first fragment or
	// whole packet of TCP.
	HasFlags bool
	// ICMPType is the ICMP or ICMPv6 type, after ReadICMP.
	ICMPType uint8
	// HasICMPType is whether the packet carries it, a first fragment or whole
	// packet of ICMP or ICMPv6.
	HasICMPType bool
	// Fragment is whether the packet is a non-first fragment, after
	// ReadFragment.
	Fragment bool

	ports, tcp, icmp, fragmentation bool
}

// Read takes the fields every rule looks at from the packet.
//
// The fields are filled in place: they are wide enough that returning them
// would copy the whole struct into the caller's frame once per check. The
// family of each address is decided here as well, so that a target tells an
// address of its own family from any other without looking at the address.
func (m *packetFields) Read(pkt Packet) {
	m.Version = pkt.Version()
	m.Protocol = pkt.Protocol()
	m.Source = pkt.SourceAddr()
	m.Destination = pkt.DestinationAddr()
	m.SourceFamily = addrFamily(m.Source)
	m.DestinationFamily = addrFamily(m.Destination)
}

// addrFamily is the family of an address, the zero value being neither,
// which is what an invalid address is.
func addrFamily(addr netip.Addr) IPVersion {
	switch {
	case addr.Is4():
		return IPv4
	case addr.Is6():
		return IPv6
	}
	return 0
}

// ReadPorts takes the ports on first use, of a first fragment or a whole
// packet of TCP, UDP, SCTP or UDP-Lite only, the protocols ipfw_chk reads
// ports of.
//
// The check of a later use stays small enough to inline at every matcher,
// the reading itself being a call of its own, as for the flags and the type.
func (m *packetFields) ReadPorts(pkt Packet) {
	if !m.ports {
		m.readPorts(pkt)
	}
}

func (m *packetFields) readPorts(pkt Packet) {
	m.ports = true
	switch m.Protocol {
	case protoTCP, protoUDP, protoSCTP, protoUDPLite:
	default:
		return
	}
	if m.ReadFragment(pkt); m.Fragment {
		return
	}
	m.SourcePort, m.HasSourcePort = pkt.SourcePort()
	m.DestinationPort, m.HasDestinationPort = pkt.DestinationPort()
}

// ReadFlags takes the TCP flags on first use, of a first fragment or a whole
// packet of TCP only.
func (m *packetFields) ReadFlags(pkt Packet) {
	if !m.tcp {
		m.readFlags(pkt)
	}
}

func (m *packetFields) readFlags(pkt Packet) {
	m.tcp = true
	if m.Protocol != protoTCP {
		return
	}
	if m.ReadFragment(pkt); m.Fragment {
		return
	}
	m.Flags, m.HasFlags = pkt.TCPFlags()
}

// ReadICMP takes the ICMP or ICMPv6 type on first use, of a first fragment or
// a whole packet of either only.
func (m *packetFields) ReadICMP(pkt Packet) {
	if !m.icmp {
		m.readICMP(pkt)
	}
}

func (m *packetFields) readICMP(pkt Packet) {
	m.icmp = true
	if m.Protocol != protoICMP && m.Protocol != protoICMPv6 {
		return
	}
	if m.ReadFragment(pkt); m.Fragment {
		return
	}
	m.ICMPType, m.HasICMPType = pkt.ICMPType()
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
	hasIPProtos := !rule.IPProtos.Empty()
	hasProtos := !rule.Protos.Empty()
	if hasIPProtos && hasProtos {
		if !matchIPProtos(program.IPProtos(rule.IPProtos), fields.Version) &&
			!matchProtos(program.Protos(rule.Protos), fields.Protocol) {
			return false, noTarget
		}
	} else {
		if hasIPProtos && !matchIPProtos(program.IPProtos(rule.IPProtos), fields.Version) {
			return false, noTarget
		}
		if hasProtos && !matchProtos(program.Protos(rule.Protos), fields.Protocol) {
			return false, noTarget
		}
	}
	// The family of the address picks the scan of its side, a branch here
	// rather than one inside the loop of every target.
	sources := program.Sources(rule.Sources)
	if fields.SourceFamily == IPv6 {
		if !m.matchTargets6(sources, ctx, fields.Source) {
			return false, noTarget
		}
	} else if !m.matchTargets4(sources, ctx, fields.Source, fields.SourceFamily) {
		return false, noTarget
	}
	destinations := program.Destinations(rule.Destinations)
	if fields.DestinationFamily == IPv6 {
		if !m.matchTargets6(destinations, ctx, fields.Destination) {
			return false, noTarget
		}
	} else if !m.matchTargets4(destinations, ctx, fields.Destination, fields.DestinationFamily) {
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

// The tablearg targets naming no rule. noTarget is that of a rule no table
// lookup of which found an entry, unnamedTarget that of an entry whose value
// names no rule, which still replaces the target of an earlier lookup.
const (
	noTarget      = -1
	unnamedTarget = -2
)

// matchOptions folds the options as ipfw(8) does: every or-block has to hold,
// a block holds when one of its match patterns does, and a pattern holds when
// one of its members matches, its negation aside.
//
// A block that holds skips its remaining patterns and a pattern that matched
// its remaining members, as the kernel skips the rest of an or-block and of a
// list. The target comes from the last successful table lookup evaluated.
func (m *VM[V4, V6]) matchOptions(
	options []ipfw.Opt,
	ctx *Context,
	pkt Packet,
	fields *packetFields,
) (bool, int) {
	target := noTarget
	for idx := 0; idx < len(options); {
		first := &options[idx]
		matched, found := m.matchOption(first, ctx, pkt, fields)
		if found != noTarget {
			target = found
		}
		// The members after the first are a list, most often of ports, which
		// are compared in place as the kernel scans the ports of one
		// instruction, without a call per member.
		more := false
		end := idx + 1
		for ; end < len(options) && options[end].Block == first.Block; end++ {
			opt := &options[end]
			if opt.Pattern != first.Pattern {
				more = true
				break
			}
			switch {
			case matched:
			case opt.Kind == ipfw.OptSourcePort:
				fields.ReadPorts(pkt)
				matched = fields.HasSourcePort && inRange(fields.SourcePort, opt.Ports)
			case opt.Kind == ipfw.OptDestinationPort:
				fields.ReadPorts(pkt)
				matched = fields.HasDestinationPort && inRange(fields.DestinationPort, opt.Ports)
			default:
				if matched, found = m.matchOption(opt, ctx, pkt, fields); found != noTarget {
					target = found
				}
			}
		}
		if matched != first.Neg {
			for more && end < len(options) && options[end].Block == first.Block {
				end++
			}
		} else if !more {
			return false, noTarget
		}
		idx = end
	}
	return true, target
}

// matchOption reports whether the option, its negation aside, holds for
// the packet in the context, and the tablearg target it yields.
//
// established is a TCP packet with ACK or RST set, tcpflags one satisfying
// its set and clear requirements, src-port and dst-port a packet whose port
// is in the range, proto one of the protocol number, in and out the direction
// of the check, via the context's interface by name, by mask or through a
// table, frag a non-first fragment, icmptypes an ICMP packet of a type in the
// set, and icmp6types an IPv6 ICMPv6 packet of a type in the set. A transport
// field holds only on a first fragment or a whole packet, as in ipfw_chk.
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
		return fields.HasFlags &&
			fields.Flags&opt.TCPFlags.Set == opt.TCPFlags.Set &&
			fields.Flags&opt.TCPFlags.Clear == 0, noTarget
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
		return fields.Protocol == protoICMP && fields.HasICMPType &&
			opt.Types.Has(fields.ICMPType), noTarget
	case ipfw.OptICMP6Types:
		fields.ReadICMP(pkt)
		return fields.Version == IPv6 && fields.Protocol == protoICMPv6 && fields.HasICMPType &&
			opt.Types.Has(fields.ICMPType), noTarget
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
// of no consequence to the verdict. A comment holds, being no condition, so
// a negated one fails its rule.
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
// A mask like `*` takes even no interface at all. The value written in the
// option is not consulted, as ipfw(8) drops it.
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
		return true, m.tableTarget(value)
	}
	return false, noTarget
}

// tableTarget is the tablearg target the value of a table entry names: a
// number the first rule numbered at or after it, as in ipfw(8), and a label
// the rule after it, unnamedTarget when no label is so named.
func (m *VM[V4, V6]) tableTarget(value string) int {
	if number, ok := ruleNumber(value); ok {
		return m.program.At(number)
	}
	if target, ok := m.labels[value]; ok {
		return target
	}
	return unnamedTarget
}

// ruleNumber reads a table value of decimal digits as a rule number, false
// for any other value.
func ruleNumber(value string) (uint64, bool) {
	if value == "" || len(value) > 10 {
		return 0, false
	}
	var number uint64
	for idx := range len(value) {
		digit := value[idx] - '0'
		if digit > 9 {
			return 0, false
		}
		number = number*10 + uint64(digit)
	}
	return number, number <= math.MaxUint32
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

// matchTargets4 reports whether the address, which is IPv4 or of no family
// at all, is one of the targets, none matching nothing.
//
// The consecutive targets of one pattern are alternatives: the address is in
// any of them, or in none when the pattern is negated. A side left empty by a
// name standing for nothing is a rule that never matches. An address of no
// family is in no network, which family tells apart.
//
// The scan is written once per family, matchTargets6 being the other one, so
// that its loop tests the networks of one family and skips those of the other
// on their kind alone. That keeps a call out of the loop where a long scan
// spends most of its time, while the wider IPv6 network, which the call has
// to put in four registers, stays out of the way of the IPv4 one.
func (m *VM[V4, V6]) matchTargets4(
	targets []ipfw.TargetMatch[V4, V6],
	ctx *Context,
	addr netip.Addr,
	family IPVersion,
) bool {
	idx := 0
	for idx < len(targets) {
		first := &targets[idx]
		hit := false
		for {
			target := &targets[idx]
			switch target.Kind {
			case ipfw.TargetNetwork4:
				hit = hit || family == IPv4 && target.Net4.ContainsAddr(addr)
			case ipfw.TargetNetwork6:
				// An IPv6 network holds no address this scan is given.
			case ipfw.TargetAny:
				hit = true
			default:
				hit = hit || m.matchNamedTarget(target, ctx, addr, family)
			}
			idx++
			if idx == len(targets) || targets[idx].Pattern != first.Pattern {
				break
			}
		}
		if hit != first.Neg {
			return true
		}
	}
	return false
}

// matchTargets6 is matchTargets4 for an address that is an IPv6 one.
func (m *VM[V4, V6]) matchTargets6(
	targets []ipfw.TargetMatch[V4, V6],
	ctx *Context,
	addr netip.Addr,
) bool {
	idx := 0
	for idx < len(targets) {
		first := &targets[idx]
		hit := false
		for {
			target := &targets[idx]
			switch target.Kind {
			case ipfw.TargetNetwork6:
				hit = hit || target.Net6.ContainsAddr(addr)
			case ipfw.TargetNetwork4:
				// An IPv4 network holds no address this scan is given.
			case ipfw.TargetAny:
				hit = true
			default:
				hit = hit || m.matchNamedTarget(target, ctx, addr, IPv6)
			}
			idx++
			if idx == len(targets) || targets[idx].Pattern != first.Pattern {
				break
			}
		}
		if hit != first.Neg {
			return true
		}
	}
	return false
}

// matchNamedTarget reports whether the address is the target's, for the
// kinds a scan meets rarely, family being the one the check found the
// address to belong to.
//
// me and me6 are the context's addresses of the packet's family, a
// missing table holds nothing.
func (m *VM[V4, V6]) matchNamedTarget(
	target *ipfw.TargetMatch[V4, V6],
	ctx *Context,
	addr netip.Addr,
	family IPVersion,
) bool {
	switch target.Kind {
	case ipfw.TargetMe:
		return family == IPv4 && slices.Contains(ctx.LocalAddrs, addr)
	case ipfw.TargetMe6:
		return family == IPv6 && slices.Contains(ctx.LocalAddrs, addr)
	case ipfw.TargetTable:
		_, ok := m.tables.LookupNetwork(target.Name, addr)
		return ok
	}
	return false
}

// addressTarget is the tablearg target the address lookups of the matched
// rule at pc yield, the destination looked up after the source as in
// ipfw_chk, noTarget when none found an entry.
//
// The scans that match the addresses keep no target, no other rule needing
// one, so the addresses are scanned again here, the destination first, as the
// later lookup is the one that counts. The rule comes by its index, which the
// check keeps anyway, where its address would cost a store per rule.
func (m *VM[V4, V6]) addressTarget(pc int, ctx *Context, fields *packetFields) int {
	program := &m.program
	rule := &program.Rules()[pc]
	destinations := program.Destinations(rule.Destinations)
	target := m.lookupTargets(destinations, ctx, fields.Destination, fields.DestinationFamily)
	if target != noTarget {
		return target
	}
	return m.lookupTargets(program.Sources(rule.Sources), ctx, fields.Source, fields.SourceFamily)
}

// lookupTargets is the tablearg target of the table lookups that a scan of the
// targets for the address makes, noTarget when none finds an entry.
//
// The scan stops where matchTargets4 and matchTargets6 stop, at the first
// alternative the address is in and at the first pattern that holds, looking
// up no table past them, as ipfw_chk skips the rest of an or-block. A lookup
// that finds an entry names the target under a negation too.
func (m *VM[V4, V6]) lookupTargets(
	targets []ipfw.TargetMatch[V4, V6],
	ctx *Context,
	addr netip.Addr,
	family IPVersion,
) int {
	found := noTarget
	for idx := 0; idx < len(targets); {
		first := &targets[idx]
		hit := false
		for ; idx < len(targets) && targets[idx].Pattern == first.Pattern; idx++ {
			target := &targets[idx]
			switch {
			case hit:
			case target.Kind == ipfw.TargetTable:
				var value string
				if value, hit = m.tables.LookupNetwork(target.Name, addr); hit {
					found = m.tableTarget(value)
				}
			case target.Kind == ipfw.TargetNetwork4:
				hit = family == IPv4 && target.Net4.ContainsAddr(addr)
			case target.Kind == ipfw.TargetNetwork6:
				hit = family == IPv6 && target.Net6.ContainsAddr(addr)
			case target.Kind == ipfw.TargetAny:
				hit = true
			default:
				hit = m.matchNamedTarget(target, ctx, addr, family)
			}
		}
		if hit != first.Neg {
			break
		}
	}
	return found
}
