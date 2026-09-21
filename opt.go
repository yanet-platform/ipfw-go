package ipfw

import "strings"

// OptKind names a rule option.
type OptKind uint8

// The rule options. OptCustom is produced by an option hook.
//
// OptComment is `//` with the rest of the line up to any `#` as its text, the
// leading space kept and the trailing whitespace removed. Taking the rest of
// the line, it ends the option list and leaves any group it stands in unclosed.
const (
	_ OptKind = iota
	OptComment
	OptDiverted
	OptSourcePort
	OptDestinationPort
	OptEstablished
	OptFrag
	OptICMPTypes
	OptICMP6Types
	OptIn
	OptOut
	OptKeepState
	OptProto
	OptTCPFlags
	OptVia
	OptAntiSpoof
	OptCustom
)

// String returns the ipfw keyword of the option, empty for the zero value.
func (m OptKind) String() string {
	switch m {
	case OptComment:
		return "//"
	case OptDiverted:
		return "diverted"
	case OptSourcePort:
		return "src-port"
	case OptDestinationPort:
		return "dst-port"
	case OptEstablished:
		return "established"
	case OptFrag:
		return "frag"
	case OptICMPTypes:
		return "icmptypes"
	case OptICMP6Types:
		return "icmp6types"
	case OptIn:
		return "in"
	case OptOut:
		return "out"
	case OptKeepState:
		return "keep-state"
	case OptProto:
		return "proto"
	case OptTCPFlags:
		return "tcpflags"
	case OptVia:
		return "via"
	case OptAntiSpoof:
		return "antispoof"
	case OptCustom:
		return "custom"
	default:
		return ""
	}
}

// ParseOptions parses the trailing option list of a rule body into state.
//
// The hook takes the keywords the grammar does not know, nil leaving them
// unknown. Its input ends before the first LF or CRLF. The or-blocks are
// numbered from zero, so the options of one rule go through one call. It
// returns the number of bytes consumed, or on failure its offset together with
// the error, an ErrorKind unless the state returned something else.
func ParseOptions(s string, state State, hook OptionHook) (int, error) {
	line, afterLine := takeLine(s)
	if afterLine != "" && strings.HasSuffix(line, "\r") {
		line = line[:len(line)-1]
	}
	var ctx optionContext
	rest, err := parseOptions(&ctx, line, state, hook)
	return consumed(line, rest, err)
}

// parseOptions parses the option list up to the end of the input or of the
// line.
//
// Every option is handed to the state as it is read, so the ones before a
// failure stay in the state. The or-blocks are numbered on from the context.
func parseOptions(ctx *optionContext, s string, state State, hook OptionHook) (string, fail) {
	rest := s
	var ok bool
	for rest != "" && rest[0] != '\n' && !hasPrefix(rest, "\r\n") {
		buf, err := parseOptionGroup(ctx, rest, state, hook)
		if err.Failed() {
			return s, err
		}
		if rest, ok = ws1(buf); !ok {
			return rest, fail{}
		}
	}
	return rest, fail{}
}

// optionPlace is where an option stands in its option list, which every
// option it gives the state carries: the match pattern in the low sixteen
// bits, the or-block in the next sixteen and whether the block is braced.
//
// One word takes one register through the option parsers, whose other
// arguments already fill most of the nine the ABI passes in registers.
type optionPlace uint64

// placeBraced marks a place inside a `{ … }` group.
const placeBraced optionPlace = 1 << 32

// Braced reports whether the place is inside a `{ … }` group.
func (m optionPlace) Braced() bool {
	return m&placeBraced != 0
}

// Block is the or-block of the place.
func (m optionPlace) Block() uint16 {
	return uint16(m >> 16)
}

// Pattern is the match pattern of the place within its block.
func (m optionPlace) Pattern() uint16 {
	return uint16(m)
}

// NextPattern returns the place of the next match pattern of the block.
func (m optionPlace) NextPattern() optionPlace {
	return m&^0xffff | optionPlace(uint16(m)+1)
}

// Opt returns an option of the kind standing in the place.
func (m optionPlace) Opt(neg bool, kind OptKind) Opt {
	return Opt{Neg: neg, Block: m.Block(), Pattern: m.Pattern(), Kind: kind}
}

// optionContext is what the options of one rule share: the or-blocks given
// so far and whether one of them created state.
type optionContext struct {
	blocks           uint16
	dynamicStateSeen bool
}

// Place returns the place of the first match pattern of the next or-block.
func (m *optionContext) Place(braced bool) optionPlace {
	place := optionPlace(m.blocks) << 16
	if braced {
		place |= placeBraced
	}
	return place
}

// EndBlock moves on to the next or-block.
func (m *optionContext) EndBlock() {
	m.blocks++
}

// Validate rejects a dynamic state option in an OR group or after one
// already accepted in the same rule.
func (m *optionContext) Validate(kind OptKind, place optionPlace, at string) fail {
	if kind != OptKeepState {
		return fail{}
	}
	if place.Braced() {
		return fail{Kind: ErrDynamicStateInGroup, At: at}
	}
	if m.dynamicStateSeen {
		return fail{Kind: ErrDuplicateDynamicState, At: at}
	}
	m.dynamicStateSeen = true
	return fail{}
}

// parseOptionGroup parses one option or a `{ a or b … }` group of them as
// the next or-block, every member a match pattern of its own.
func parseOptionGroup(
	ctx *optionContext,
	s string,
	state State,
	hook OptionHook,
) (string, fail) {
	g, rest := openGroup(s, trailingPosition)
	place := ctx.Place(g.Braced)
	for {
		buf, err := parseOption(ctx, rest, state, hook, place)
		if err.Failed() {
			return s, err
		}
		var more bool
		if rest, more, err = g.Next(buf); err.Failed() {
			return s, err
		}
		if !more {
			ctx.EndBlock()
			return rest, fail{}
		}
		place = place.NextPattern()
	}
}

// parseOption parses one optionally negated option, with a failure pointing
// at the keyword.
func parseOption(
	ctx *optionContext,
	s string,
	state State,
	hook OptionHook,
	place optionPlace,
) (string, fail) {
	rest, neg := notWS1(s)
	var buf string
	var err fail
	kind, n := argumentOption(rest)
	arg := rest[n:]
	if err = ctx.Validate(kind, place, rest); err.Failed() {
		return s, err
	}
	switch kind {
	case OptComment:
		buf, err = parseCommentOption(rest, state, neg, place)
	case OptSourcePort, OptDestinationPort:
		buf, err = parsePortsOption(arg, state, kind, neg, place)
	case OptICMPTypes, OptICMP6Types:
		buf, err = parseTypesOption(arg, state, kind, neg, place)
	case OptKeepState:
		buf, err = parseKeepStateOption(arg, state, neg, place)
	case OptProto:
		buf, err = parseProtoOption(arg, state, neg, place)
	case OptTCPFlags:
		buf, err = parseTCPFlagsOption(arg, state, neg, place)
	case OptVia:
		buf, err = parseViaOption(arg, state, neg, place)
	default:
		buf, err = parseKeywordOption(ctx, rest, state, hook, neg, place)
	}
	if err.Failed() {
		return s, err
	}
	return buf, fail{}
}

// argumentOption tells an option with an argument by its complete keyword
// and returns its kind with the keyword's length, zero for none.
func argumentOption(s string) (OptKind, int) {
	if s == "" {
		return 0, 0
	}
	switch s[0] {
	case '/':
		if hasPrefix(s, "//") {
			return OptComment, len("//")
		}
	case 's':
		if _, ok := optionKeyword(s, "src-port"); ok {
			return OptSourcePort, len("src-port")
		}
	case 'd':
		if _, ok := optionKeyword(s, "dst-port"); ok {
			return OptDestinationPort, len("dst-port")
		}
	case 'i':
		if _, ok := optionKeyword(s, "icmptypes"); ok {
			return OptICMPTypes, len("icmptypes")
		}
		if _, ok := optionKeyword(s, "icmptype"); ok {
			return OptICMPTypes, len("icmptype")
		}
		if _, ok := optionKeyword(s, "icmp6types"); ok {
			return OptICMP6Types, len("icmp6types")
		}
		if _, ok := optionKeyword(s, "icmp6type"); ok {
			return OptICMP6Types, len("icmp6type")
		}
	case 'k':
		if _, ok := optionKeyword(s, "keep-state"); ok {
			return OptKeepState, len("keep-state")
		}
	case 'p':
		if _, ok := optionKeyword(s, "proto"); ok {
			return OptProto, len("proto")
		}
	case 't':
		if _, ok := optionKeyword(s, "tcpflags"); ok {
			return OptTCPFlags, len("tcpflags")
		}
		if _, ok := optionKeyword(s, "tcpflgs"); ok {
			return OptTCPFlags, len("tcpflgs")
		}
	case 'v':
		if _, ok := optionKeyword(s, "via"); ok {
			return OptVia, len("via")
		}
	}
	return 0, 0
}

// parseKeywordOption parses an option without an argument, the hook
// taking a keyword the grammar does not know.
func parseKeywordOption(
	ctx *optionContext,
	s string,
	state State,
	hook OptionHook,
	neg bool,
	place optionPlace,
) (string, fail) {
	kind, rest, ok := keywordOption(s)
	if !ok {
		return parseCustomOption(ctx, s, state, hook, neg, place)
	}
	if err := failFrom(state.OnOption(place.Opt(neg, kind)), s); err.Failed() {
		return s, err
	}
	return rest, fail{}
}

// parseCustomOption hands an unknown keyword to the hook, reserving the
// negation and the place for the parser to set on what the hook returns.
func parseCustomOption(
	ctx *optionContext,
	s string,
	state State,
	hook OptionHook,
	neg bool,
	place optionPlace,
) (string, fail) {
	if hook == nil {
		return s, fail{Kind: ErrUnknownOption, At: s}
	}
	opt, n, err := hook(s)
	n = min(max(n, 0), len(s))
	if err != nil {
		return s, failFrom(err, s[n:])
	}
	if n == 0 {
		return s, fail{Kind: ErrUnknownOption, At: s}
	}
	opt.Neg, opt.Block, opt.Pattern = neg, place.Block(), place.Pattern()
	if failure := ctx.Validate(opt.Kind, place, s); failure.Failed() {
		return s, failure
	}
	if failure := failFrom(state.OnOption(opt), s); failure.Failed() {
		return s, failure
	}
	return s[n:], fail{}
}

// parseCommentOption takes the rest of the line after `//` as the comment,
// a rejection pointing at the slashes.
//
// The newline stays for the line to end on, a carriage return before it
// included, so the comment never reaches the next line.
func parseCommentOption(s string, state State, neg bool, place optionPlace) (string, fail) {
	text, _ := prefix(s, "//")
	end := strings.IndexByte(text, '\n')
	if end < 0 {
		end = len(text)
	} else if end > 0 && text[end-1] == '\r' {
		end--
	}
	opt := place.Opt(neg, OptComment)
	opt.Text = trimRightSpace(text[:end])
	if err := failFrom(state.OnOption(opt), s); err.Failed() {
		return s, err
	}
	return text[end:], fail{}
}

// parseTypesOption parses the comma list of type numbers after `icmptypes`
// or `icmp6types` into one option holding them as a set.
//
// A number outside the option's numeric range is an error at that number.
// The limits follow ipfw(8) and include unassigned types.
func parseTypesOption(s string, state State, kind OptKind, neg bool, place optionPlace) (string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	var types TypeSet
	buf := rest
	for {
		ty, afterType, numberKind := parseU8(buf)
		if numberKind != 0 {
			return s, fail{Kind: numberKind, At: buf}
		}
		if !icmpTypeInRange(kind, ty) {
			return s, fail{Kind: unknownTypeKind(kind), At: buf}
		}
		types.Add(ty)
		if buf, ok = prefix(afterType, ","); !ok {
			break
		}
		buf = skipCommaSpace(buf)
		if listEnded(buf) {
			break
		}
	}
	opt := place.Opt(neg, kind)
	opt.Types = types
	if err := failFrom(state.OnOption(opt), rest); err.Failed() {
		return s, err
	}
	return buf, fail{}
}

func icmpTypeInRange(kind OptKind, number uint8) bool {
	switch kind {
	case OptICMPTypes:
		return number <= 31
	case OptICMP6Types:
		return number <= 201
	}
	return false
}

// unknownTypeKind is the error of a type number the option kind does not
// accept.
func unknownTypeKind(kind OptKind) ErrorKind {
	if kind == OptICMP6Types {
		return ErrUnknownICMP6Type
	}
	return ErrUnknownICMPType
}

// parseKeepStateOption parses the optional ` :flow` after `keep-state`.
func parseKeepStateOption(s string, state State, neg bool, place optionPlace) (string, fail) {
	flow, rest, _ := parseFlowName(s)
	opt := place.Opt(neg, OptKeepState)
	opt.Text = flow
	if err := failFrom(state.OnOption(opt), s); err.Failed() {
		return s, err
	}
	return rest, fail{}
}

// parseProtoOption parses the protocol after `proto`.
func parseProtoOption(s string, state State, neg bool, place optionPlace) (string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	proto, buf, kind := parseProto(rest)
	if kind != 0 {
		return s, fail{Kind: kind, At: rest}
	}
	opt := place.Opt(neg, OptProto)
	opt.Proto = proto
	if err := failFrom(state.OnOption(opt), rest); err.Failed() {
		return s, err
	}
	return buf, fail{}
}

// parseTCPFlagsOption parses the comma list of `[!]flag` after `tcpflags`
// into one option.
//
// A bang separates flags that must be clear from those that must be set.
func parseTCPFlagsOption(s string, state State, neg bool, place optionPlace) (string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	var flags TCPFlags
	buf := rest
	for {
		afterBang, cleared := prefix(buf, "!")
		flag, afterFlag, ok := tcpFlagByName(afterBang)
		if !ok {
			return s, fail{Kind: ErrUnknownTCPFlag, At: afterBang}
		}
		if cleared {
			flags.Clear |= flag
		} else {
			flags.Set |= flag
		}
		if buf, ok = prefix(afterFlag, ","); !ok {
			break
		}
		buf = skipCommaSpace(buf)
		if listEnded(buf) {
			break
		}
	}
	opt := place.Opt(neg, OptTCPFlags)
	opt.TCPFlags = flags
	if err := failFrom(state.OnOption(opt), rest); err.Failed() {
		return s, err
	}
	return buf, fail{}
}

// tcpFlagNames are the flag keywords in the order they are tried.
var tcpFlagNames = [...]struct {
	name string
	flag TCPFlag
}{
	{"fin", TCPFin},
	{"syn", TCPSyn},
	{"rst", TCPRst},
	{"psh", TCPPsh},
	{"ack", TCPAck},
	{"urg", TCPUrg},
}

// tcpFlagByName tells a TCP flag by its keyword, matching by prefix.
func tcpFlagByName(s string) (TCPFlag, string, bool) {
	for idx := range tcpFlagNames {
		if rest, ok := prefix(s, tcpFlagNames[idx].name); ok {
			return tcpFlagNames[idx].flag, rest, true
		}
	}
	return 0, s, false
}

// parseViaOption parses the interface after `via`.
func parseViaOption(s string, state State, neg bool, place optionPlace) (string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	via, buf, err := parseVia(rest)
	if err.Failed() {
		return s, err
	}
	opt := place.Opt(neg, OptVia)
	opt.Via = via
	if err = failFrom(state.OnOption(opt), rest); err.Failed() {
		return s, err
	}
	return buf, fail{}
}

// parseVia reads a `table(NAME[,VALUE])` lookup or an interface name, a
// mask when it holds a glob byte.
//
// A mask has to be one ipfw(8) accepts.
func parseVia(s string) (Via, string, fail) {
	if buf, ok := prefix(s, "table("); ok {
		via, rest, err := parseViaTable(buf)
		if err.Failed() {
			return Via{}, s, err
		}
		return via, rest, fail{}
	}
	name, rest := takeWhile(s, isIfNameByte)
	if name == "" {
		return Via{}, s, fail{Kind: ErrExpectedOpt, At: s}
	}
	if !strings.ContainsAny(name, "*?[]") {
		return Via{Kind: ViaExact, Name: name}, rest, fail{}
	}
	return Via{Kind: ViaMask, Name: name}, rest, fail{}
}

func isIfNameByte(c byte) bool {
	return !isASCIISpace(c) && c != '/' && c != '{' && c != '}'
}

// parseViaTable reads the `NAME[,VALUE])` of a table lookup after the
// opening parenthesis.
//
// Both parts run up to whitespace or the closing parenthesis, the name up
// to a comma as well.
func parseViaTable(s string) (Via, string, fail) {
	name, rest := takeWhile(s, isTableNameByte)
	if name == "" {
		return Via{}, s, fail{Kind: ErrExpectedTableName, At: s}
	}
	via := Via{Kind: ViaTable, Name: name}
	if buf, ok := prefix(rest, ","); ok {
		via.Value, rest = takeWhile(buf, isTableValueByte)
		if via.Value == "" {
			return Via{}, s, fail{Kind: ErrExpectedTableValue, At: buf}
		}
	}
	rest, ok := prefix(rest, ")")
	if !ok {
		return Via{}, s, fail{Kind: ErrExpectedPrefix, At: rest}
	}
	return via, rest, fail{}
}

func isTableNameByte(c byte) bool {
	return !isASCIISpace(c) && c != ')' && c != ','
}

func isTableValueByte(c byte) bool {
	return !isASCIISpace(c) && c != ')'
}

// parsePortsOption parses the port list after `src-port` or `dst-port`,
// one callback per range.
//
// The ranges are the members of one match pattern, sharing its place and
// its negation, as one ipfw(8) instruction holds them all.
func parsePortsOption(
	s string,
	state State,
	kind OptKind,
	neg bool,
	place optionPlace,
) (string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	for {
		portRange, buf, err := parsePortRange(rest)
		if err.Failed() {
			return s, err
		}
		opt := place.Opt(neg, kind)
		opt.Ports = portRange
		if err = failFrom(state.OnOption(opt), rest); err.Failed() {
			return s, err
		}
		if buf, ok = prefix(buf, ","); !ok {
			return buf, fail{}
		}
		rest = skipCommaSpace(buf)
		if listEnded(rest) {
			return rest, fail{}
		}
	}
}

// keywordOption tells an option without an argument by its complete keyword.
func keywordOption(s string) (OptKind, string, bool) {
	if s == "" {
		return 0, s, false
	}
	var keyword string
	var kind OptKind
	switch s[0] {
	case 'a':
		keyword, kind = "antispoof", OptAntiSpoof
	case 'd':
		keyword, kind = "diverted", OptDiverted
	case 'e':
		if rest, ok := optionKeyword(s, "established"); ok {
			return OptEstablished, rest, true
		}
		keyword, kind = "estab", OptEstablished
	case 'f':
		if rest, ok := optionKeyword(s, "fragment"); ok {
			return OptFrag, rest, true
		}
		keyword, kind = "frag", OptFrag
	case 'i':
		keyword, kind = "in", OptIn
	case 'o':
		keyword, kind = "out", OptOut
	default:
		return 0, s, false
	}
	rest, ok := optionKeyword(s, keyword)
	if !ok {
		return 0, s, false
	}
	return kind, rest, true
}

// optionKeyword consumes a built-in spelling only at an option token boundary.
//
// Whitespace ends ordinary tokens. A closing brace ends a tight group, `//`
// starts an adjacent comment, and `|` ends a member only as a complete separator.
func optionKeyword(s, keyword string) (string, bool) {
	rest, ok := prefix(s, keyword)
	if !ok {
		return s, false
	}
	if rest == "" || isASCIISpace(rest[0]) || rest[0] == '}' || hasPrefix(rest, "//") {
		return rest, true
	}
	if rest[0] == '|' && atTokenEnd(rest[1:]) {
		return rest, true
	}
	return s, false
}

// Opt is one rule option with the argument of its kind.
type Opt struct {
	// Neg is the `not` prefix, shared by the members of a pattern.
	Neg bool
	// Block is the index, from zero, of the or-block the option belongs to
	// within its option list: an option on its own is a block of one, and
	// every block has to hold. The options of a block are contiguous, and a
	// command hook handing options to the state itself numbers them so.
	Block uint16
	// Pattern is the index, from zero, of the match pattern the option
	// belongs to within its block: the alternatives of a `{ a or b }` group
	// count up, the members of a list share one, and so does their `not`.
	Pattern uint16
	// Kind is the option.
	Kind OptKind
	// Text is the comment after `//`, the keep-state flow name or the custom
	// keyword.
	Text string
	// Arg is the raw argument of a custom option.
	Arg string
	// Ports is the src-port or dst-port range.
	Ports PortRange
	// Proto is the proto argument.
	Proto Proto
	// Types is the icmptypes or icmp6types set.
	Types TypeSet
	// TCPFlags is the tcpflags argument.
	TCPFlags TCPFlags
	// Via is the via argument.
	Via Via
}

// TypeSet is a set of ICMP or ICMPv6 type numbers, the zero value empty.
type TypeSet struct {
	bits [4]uint64
}

// Add puts ty into the set.
func (m *TypeSet) Add(ty uint8) {
	m.bits[ty>>6] |= 1 << (ty & 63)
}

// Has reports whether ty is in the set.
func (m TypeSet) Has(ty uint8) bool {
	return m.bits[ty>>6]&(1<<(ty&63)) != 0
}

// IsEmpty reports whether the set has no types.
func (m TypeSet) IsEmpty() bool {
	return m == TypeSet{}
}

// TCPFlag is a TCP header flag at its wire bit position.
type TCPFlag uint8

// The TCP flags.
const (
	TCPFin TCPFlag = 1 << iota
	TCPSyn
	TCPRst
	TCPPsh
	TCPAck
	TCPUrg
)

// TCPFlags is the set of requirements in a `tcpflags` argument.
type TCPFlags struct {
	// Set contains the flags that must be set.
	Set TCPFlag
	// Clear contains the flags that must be clear.
	Clear TCPFlag
}

// ViaKind is how a `via` option names interfaces.
type ViaKind uint8

// The via argument kinds: an exact name, a glob mask or a table lookup.
const (
	_ ViaKind = iota
	ViaExact
	ViaMask
	ViaTable
)

// Via is the argument of a `via` option.
type Via struct {
	// Kind is how the interfaces are named.
	Kind ViaKind
	// Name is the interface name, the mask pattern or the table name.
	Name string
	// Value is the optional value of a `table(name,value)` lookup.
	Value string
}
