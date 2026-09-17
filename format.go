package ipfw

import (
	"strconv"
	"strings"
)

// formatterOptions is what a FormatterOption configures.
type formatterOptions struct {
	// CustomOpt appends custom option syntax, nil rejecting it.
	CustomOpt CustomOptAppender
}

func newFormatterOptions() formatterOptions {
	return formatterOptions{}
}

// FormatterOption configures a Formatter, see the With functions.
type FormatterOption func(*formatterOptions)

// CustomOptAppender writes syntax the built-in formatter cannot reconstruct.
//
// Formatter writes negation and group punctuation. The appender handles
// OptCustom and an OptComment returned by OptionHook when `//` would change
// the option sequence. It must append one line without `#`, preserve the
// supplied prefix, and return that prefix unchanged on error.
type CustomOptAppender func(dst []byte, opt Opt) ([]byte, error)

// WithCustomOptAppender hands custom option syntax to appender.
func WithCustomOptAppender(appender CustomOptAppender) FormatterOption {
	return func(opts *formatterOptions) {
		opts.CustomOpt = appender
	}
}

// Formatter renders parsed records into canonical ruleset text.
type Formatter struct {
	opts formatterOptions
}

// NewFormatter returns a formatter over parsed records.
func NewFormatter(options ...FormatterOption) *Formatter {
	opts := newFormatterOptions()
	for _, option := range options {
		option(&opts)
	}
	return &Formatter{opts: opts}
}

// AppendRecord appends the canonical text of one record without its final
// newline.
//
// An empty record appends nothing. On error the returned slice and its existing
// bytes are unchanged, while bytes in unused capacity may hold attempted output.
func (m *Formatter) AppendRecord(dst []byte, record ParsedRecord) ([]byte, error) {
	buf, err := m.appendRecord(dst, record)
	if err != nil {
		return dst, err
	}
	return buf, nil
}

// AppendRuleset appends the records in order, one newline per record, so an
// empty record contributes only its newline.
//
// On error the returned slice and its existing bytes are unchanged, while bytes
// in unused capacity may hold attempted output.
func (m *Formatter) AppendRuleset(dst []byte, records []ParsedRecord) ([]byte, error) {
	buf := dst
	for idx := range records {
		var err error
		buf, err = m.appendRecord(buf, records[idx])
		if err != nil {
			return dst, err
		}
		buf = append(buf, '\n')
	}
	return buf, nil
}

// Record returns the canonical text of one record without its final
// newline, or an error the record cannot produce.
func (m *Formatter) Record(record ParsedRecord) (string, error) {
	buf, err := m.appendRecord(nil, record)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func (m *Formatter) appendRecord(dst []byte, record ParsedRecord) ([]byte, error) {
	if err := requireNoStrayFields(record); err != nil {
		return dst, err
	}
	var buf []byte
	var err error
	switch record.Record.Kind {
	case RecordEmpty:
		buf = dst
	case RecordComment:
		buf, err = appendComment(dst, record.Record.Comment)
	case RecordLabel:
		buf, err = appendLabel(dst, record.Record.Label)
	case RecordInstruction:
		buf, err = m.appendInstruction(dst, record)
	case RecordTable:
		buf, err = appendTable(dst, record.Record.Table)
	default:
		return dst, ErrUnknownRecordKind
	}
	if err != nil {
		return dst, err
	}
	if record.Record.Kind != RecordComment && record.Record.Comment != "" {
		return appendHashComment(buf, record.Record.Comment)
	}
	return buf, nil
}

// requireNoStrayFields rejects the fields and the body a record kind cannot
// hold, which the parser never produces.
func requireNoStrayFields(record ParsedRecord) error {
	rec := record.Record
	if rec.Kind != RecordInstruction && record.BodyKind != RuleBodyLegacy {
		return ErrUnexpectedBody
	}
	switch rec.Kind {
	case RecordEmpty:
		if rec.Comment != "" || rec.Label != "" ||
			rec.Instruction != (Instruction{}) || rec.Table != (Table{}) {
			return ErrUnexpectedBody
		}
	case RecordComment:
		if rec.Label != "" || rec.Instruction != (Instruction{}) || rec.Table != (Table{}) {
			return ErrUnexpectedBody
		}
	case RecordLabel:
		if rec.Instruction != (Instruction{}) || rec.Table != (Table{}) {
			return ErrUnexpectedBody
		}
	case RecordInstruction:
		if rec.Label != "" || rec.Table != (Table{}) {
			return ErrUnexpectedBody
		}
		return nil
	case RecordTable:
		if rec.Label != "" || rec.Instruction != (Instruction{}) {
			return ErrUnexpectedBody
		}
	default:
		return nil
	}
	if !record.Body.IsEmpty() {
		return ErrUnexpectedBody
	}
	return nil
}

// appendComment writes the hash and the comment text, which keeps any
// meaningful space after the hash.
func appendComment(dst []byte, comment string) ([]byte, error) {
	if !isCommentText(comment) {
		return dst, ErrInvalidName
	}
	return append(append(dst, '#'), comment...), nil
}

// appendHashComment keeps metadata adjacent when whitespace would turn a
// trailing `not` into negation.
func appendHashComment(dst []byte, comment string) ([]byte, error) {
	if !isCommentText(comment) {
		return dst, ErrInvalidName
	}
	if endsWithBareNot(dst) {
		dst = append(dst, '#')
	} else {
		dst = append(dst, " #"...)
	}
	return append(dst, comment...), nil
}

func endsWithBareNot(text []byte) bool {
	return len(text) >= 3 && isExactNot(text[len(text)-3:]) &&
		(len(text) == 3 || isASCIISpace(text[len(text)-4]))
}

func isExactNot(text []byte) bool {
	return len(text) == 3 && text[0] == 'n' && text[1] == 'o' && text[2] == 't'
}

func isCommentText(comment string) bool {
	return strings.IndexByte(comment, '\n') < 0 && trimRightSpace(comment) == comment
}

// appendLabel writes the colon and the label name.
func appendLabel(dst []byte, label string) ([]byte, error) {
	if !isTokenText(label) {
		return dst, ErrInvalidName
	}
	return append(append(dst, ':'), label...), nil
}

// isTokenText reports whether text is one non-blank token of the grammar.
func isTokenText(text string) bool {
	if text == "" || strings.IndexByte(text, '#') >= 0 {
		return false
	}
	_, rest := takeWhile(text, isTokenByte)
	return rest == ""
}

func (m *Formatter) appendInstruction(dst []byte, record ParsedRecord) ([]byte, error) {
	instruction := record.Record.Instruction
	body := record.Body
	dst = append(dst, "add "...)
	if instruction.Num != 0 {
		dst = strconv.AppendUint(dst, uint64(instruction.Num), 10)
		dst = append(dst, ' ')
	}
	if record.BodyKind == RuleBodyCommentOnly {
		if !isCommentOnlyInstruction(instruction, body) {
			return dst, ErrUnexpectedBody
		}
		comment := body.Options[0]
		if comment.Text != "" && !isASCIISpace(comment.Text[0]) {
			return dst, ErrInvalidName
		}
		return appendOpt(dst, comment, nil, false)
	}
	if record.BodyKind != RuleBodyLegacy && record.BodyKind != RuleBodyNative {
		return dst, ErrUnexpectedBody
	}
	var err error
	if dst, err = appendAction(dst, instruction.Action); err != nil {
		return dst, err
	}
	if dst, err = appendLog(dst, instruction.Log); err != nil {
		return dst, err
	}
	if instruction.Tag != 0 {
		dst = append(dst, " tag "...)
		dst = strconv.AppendUint(dst, uint64(instruction.Tag), 10)
	}
	if instruction.Action.Kind == ActionCheckState {
		if record.BodyKind != RuleBodyLegacy {
			return dst, ErrUnexpectedBody
		}
		options := body.Options
		body.Options = nil
		if !body.IsEmpty() || len(options) > 1 ||
			len(options) == 1 && !isPlainComment(options[0]) {
			return dst, ErrUnexpectedBody
		}
		if len(options) == 1 {
			dst = append(dst, ' ')
			return appendOptions(dst, options, m.opts.CustomOpt, false)
		}
		return dst, nil
	}
	if record.BodyKind == RuleBodyNative {
		if !isImplicitAnyBody(body) {
			return dst, ErrUnexpectedBody
		}
		if len(body.Options) == 0 {
			return dst, ErrUnexpectedBody
		}
		dst = append(dst, ' ')
		if dst, err = appendOptions(dst, body.Options, m.opts.CustomOpt, true); err != nil {
			return dst, err
		}
		return dst, nil
	}
	if len(body.Sources) == 0 {
		return dst, ErrMissingSource
	}
	if len(body.Destinations) == 0 {
		return dst, ErrMissingDestination
	}
	dst = append(dst, ' ')
	if dst, err = appendProtocols(dst, body); err != nil {
		return dst, err
	}
	dst = append(dst, " from "...)
	if dst, err = appendTargets(dst, body.Sources); err != nil {
		return dst, err
	}
	if len(body.SourcePorts) > 0 {
		dst = append(dst, ' ')
		if dst, err = appendPorts(dst, body.SourcePorts, sourceSide); err != nil {
			return dst, err
		}
	}
	dst = append(dst, " to "...)
	if dst, err = appendTargets(dst, body.Destinations); err != nil {
		return dst, err
	}
	if len(body.DestinationPorts) > 0 {
		dst = append(dst, ' ')
		if dst, err = appendPorts(dst, body.DestinationPorts, destinationSide); err != nil {
			return dst, err
		}
	}
	if len(body.Options) > 0 {
		dst = append(dst, ' ')
		if dst, err = appendOptions(dst, body.Options, m.opts.CustomOpt, false); err != nil {
			return dst, err
		}
	}
	return dst, nil
}

// isCommentOnlyInstruction recognizes the implicit body of an `add //` rule.
func isCommentOnlyInstruction(instruction Instruction, body ReduceState) bool {
	return instruction.Action == (Action{Kind: ActionCount}) && instruction.Log == (Log{}) &&
		instruction.Tag == 0 && isImplicitAnyBody(body) && len(body.Options) == 1 &&
		isPlainComment(body.Options[0])
}

func isPlainComment(opt Opt) bool {
	return opt.Kind == OptComment && !opt.Neg && opt.Block == 0 && opt.Pattern == 0
}

func validateCommentOptionText(comment string) error {
	if strings.ContainsAny(comment, "\n#") || trimRightSpace(comment) != comment {
		return ErrInvalidName
	}
	return nil
}

// appendAction writes the action keyword with its argument, the flow name
// of check-state included.
func appendAction(dst []byte, action Action) ([]byte, error) {
	if action.Kind != ActionCheckState && action.Flow != "" {
		return dst, ErrInvalidName
	}
	if action.Kind != ActionSkipTo && action.SkipTo != (SkipTo{}) {
		return dst, ErrUnexpectedBody
	}
	switch action.Kind {
	case ActionPass:
		return append(dst, "pass"...), nil
	case ActionDeny:
		return append(dst, "deny"...), nil
	case ActionCount:
		return append(dst, "count"...), nil
	case ActionSkipTo:
		dst = append(dst, "skipto "...)
		return appendSkipTo(dst, action.SkipTo)
	case ActionCheckState:
		dst = append(dst, "check-state"...)
		if action.Flow != "" {
			if !isTokenText(action.Flow) {
				return dst, ErrInvalidName
			}
			dst = append(dst, " :"...)
			dst = append(dst, action.Flow...)
		}
		return dst, nil
	default:
		return dst, ErrUnknownActionKind
	}
}

// appendSkipTo writes the target of a skipto: a label, a rule number or
// tablearg, the fields of the other kinds rejected.
func appendSkipTo(dst []byte, skip SkipTo) ([]byte, error) {
	switch skip.Kind {
	case SkipToLabel:
		if skip.Number != 0 {
			return dst, ErrUnexpectedBody
		}
		if !isTokenText(skip.Label) {
			return dst, ErrInvalidName
		}
		dst = append(dst, ':')
		return append(dst, skip.Label...), nil
	case SkipToNumber:
		if skip.Label != "" {
			return dst, ErrUnexpectedBody
		}
		if skip.Number == 0 {
			return dst, ErrInvalidName
		}
		return strconv.AppendUint(dst, uint64(skip.Number), 10), nil
	case SkipToTableArg:
		if skip.Label != "" || skip.Number != 0 {
			return dst, ErrUnexpectedBody
		}
		return append(dst, "tablearg"...), nil
	default:
		return dst, ErrUnknownSkipToKind
	}
}

// appendLog writes the ` log [logamount N]` part, an amount without the log
// keyword rejected.
func appendLog(dst []byte, log Log) ([]byte, error) {
	if !log.Enabled {
		if log != (Log{}) {
			return dst, ErrInvalidLog
		}
		return dst, nil
	}
	dst = append(dst, " log"...)
	if !log.HasAmount {
		if log.Amount != 0 {
			return dst, ErrInvalidLog
		}
		return dst, nil
	}
	dst = append(dst, " logamount "...)
	return strconv.AppendUint(dst, uint64(log.Amount), 10), nil
}

// appendProtocols writes the protocol section, IP version matches first and
// transport protocols after, a lone match without braces unless the header
// keywords would eat it.
func appendProtocols(dst []byte, body ReduceState) ([]byte, error) {
	total := len(body.IPProtos) + len(body.Protos)
	if total == 0 {
		return dst, ErrMissingProtocol
	}
	for idx := range body.Protos {
		if !body.Protos[idx].Neg && body.Protos[idx].Proto == (Proto{Name: "not"}) {
			return dst, ErrInvalidName
		}
	}
	braced := total > 1 || isHeaderProto(body)
	if braced {
		dst = append(dst, "{ "...)
	}
	for idx := range body.IPProtos {
		if idx > 0 {
			dst = append(dst, " or "...)
		}
		var err error
		if dst, err = appendIPProto(dst, body.IPProtos[idx]); err != nil {
			return dst, err
		}
	}
	for idx := range body.Protos {
		if len(body.IPProtos)+idx > 0 {
			dst = append(dst, " or "...)
		}
		var err error
		if dst, err = appendProto(dst, body.Protos[idx]); err != nil {
			return dst, err
		}
	}
	if braced {
		dst = append(dst, " }"...)
	}
	return dst, nil
}

// isHeaderProto reports whether the lone transport protocol extends the
// `log` or `tag` header keywords, whose prefix matching eats it unbraced.
func isHeaderProto(body ReduceState) bool {
	if len(body.IPProtos) != 0 || len(body.Protos) != 1 {
		return false
	}
	match := body.Protos[0]
	return !match.Neg && !match.Proto.IsNumber() &&
		(strings.HasPrefix(match.Proto.Name, "log") || strings.HasPrefix(match.Proto.Name, "tag"))
}

// appendIPProto writes one IP version keyword with its negation.
func appendIPProto(dst []byte, match ProtoIPMatch) ([]byte, error) {
	keyword, ok := protoIPText(match.Proto)
	if !ok {
		return dst, ErrUnknownProtoKind
	}
	if match.Neg {
		dst = append(dst, "not "...)
	}
	return append(dst, keyword...), nil
}

// protoIPText returns the keyword an IP version set renders as.
func protoIPText(version ProtoIP) (string, bool) {
	switch version {
	case ProtoIPAny:
		return "ip", true
	case ProtoIPv4:
		return "ip4", true
	case ProtoIPv6:
		return "ip6", true
	default:
		return "", false
	}
}

// appendProto writes one transport protocol by name or number, rejecting a
// name the section would not read back the same.
func appendProto(dst []byte, match ProtoMatch) ([]byte, error) {
	if match.Proto.Name == "" {
		if match.Proto.Number == 0 {
			return dst, ErrInvalidName
		}
		if match.Neg {
			dst = append(dst, "not "...)
		}
		return strconv.AppendUint(dst, uint64(match.Proto.Number), 10), nil
	}
	if !isProtoNameText(match.Proto.Name) {
		return dst, ErrInvalidName
	}
	if match.Proto.Number != 0 {
		return dst, ErrUnexpectedBody
	}
	if _, ok := protoIPKeyword(match.Proto.Name); ok {
		return dst, ErrInvalidName
	}
	if match.Neg {
		dst = append(dst, "not "...)
	}
	return append(dst, match.Proto.Name...), nil
}

// isProtoNameText reports whether text reads back as a protocol name:
// protocol bytes that are not one plain number.
func isProtoNameText(text string) bool {
	if text == "" {
		return false
	}
	if _, rest := takeWhile(text, isProtoByte); rest != "" {
		return false
	}
	if number, afterNumber, kind := parseU8(text); kind == 0 && afterNumber == "" && number > 0 {
		return false
	}
	return true
}

// appendTargets comma-joins each pattern's members and braces multiple
// alternatives.
func appendTargets(dst []byte, targets []Target) ([]byte, error) {
	if len(targets) == 0 || targets[0].Pattern != 0 {
		return dst, ErrBrokenOrChain
	}
	braced := false
	for idx := 1; idx < len(targets); idx++ {
		if targets[idx].Pattern != targets[idx-1].Pattern {
			braced = true
			break
		}
	}
	if braced {
		dst = append(dst, "{ "...)
	}
	head := 0
	for idx := range targets {
		target := targets[idx]
		if target.Pattern == targets[head].Pattern {
			if idx > 0 && (!isAddressListTarget(target) || !isAddressListTarget(targets[head])) {
				return dst, ErrBrokenOrChain
			}
			if idx > 0 && target.Neg != targets[head].Neg {
				return dst, ErrInconsistentNegation
			}
			if idx > 0 && mixedNetworkFamilies(targets[head], target) {
				return dst, ErrBrokenOrChain
			}
			if idx > 0 {
				dst = append(dst, ',')
			}
		} else {
			if target.Pattern != targets[head].Pattern+1 {
				return dst, ErrBrokenOrChain
			}
			dst = append(dst, " or "...)
			head = idx
		}
		if idx == head {
			if target.Neg {
				dst = append(dst, "not "...)
			}
		}
		var err error
		if dst, err = appendTargetText(dst, target); err != nil {
			return dst, err
		}
	}
	if braced {
		dst = append(dst, " }"...)
	}
	return dst, nil
}

func mixedNetworkFamilies(head, target Target) bool {
	return head.Kind == TargetNetwork4 && target.Kind == TargetNetwork6 ||
		head.Kind == TargetNetwork6 && target.Kind == TargetNetwork4
}

// appendTargetText writes one target by its kind, rejecting a text the
// kind would not read back from.
func appendTargetText(dst []byte, target Target) ([]byte, error) {
	switch target.Kind {
	case TargetAny:
		if target.Text != "" {
			return dst, ErrInvalidName
		}
		return append(dst, "any"...), nil
	case TargetMe:
		if target.Text != "" {
			return dst, ErrInvalidName
		}
		return append(dst, "me"...), nil
	case TargetMe6:
		if target.Text != "" {
			return dst, ErrInvalidName
		}
		return append(dst, "me6"...), nil
	case TargetTable:
		name, value, hasValue := strings.Cut(target.Text, ",")
		if !isTableRefText(name) || hasValue && !isTableValueText(value) {
			return dst, ErrInvalidName
		}
		dst = append(dst, "table("...)
		dst = append(dst, target.Text...)
		return append(dst, ')'), nil
	case TargetNetwork4:
		if !isNetwork4Text(target.Text) {
			return dst, ErrInvalidName
		}
		return append(dst, target.Text...), nil
	case TargetNetwork6:
		if !isNetwork6Text(target.Text) {
			return dst, ErrInvalidName
		}
		return append(dst, target.Text...), nil
	case TargetHostname:
		if !isHostnameText(target.Text) {
			return dst, ErrInvalidName
		}
		return append(dst, target.Text...), nil
	case TargetCustom:
		if !isCustomTargetText(target.Text) {
			return dst, ErrInvalidName
		}
		return append(dst, target.Text...), nil
	default:
		return dst, ErrUnknownTargetKind
	}
}

// isTableRefText reports whether text reads back as a non-empty table target name.
func isTableRefText(text string) bool {
	if text == "" {
		return false
	}
	for idx := range len(text) {
		if c := text[idx]; isASCIISpace(c) || c == ',' || c == '}' || c == ')' || c == '#' {
			return false
		}
	}
	return true
}

// isCustomTargetText reports whether text classifies back as a custom
// target: one token of none of the known shapes, and not one an element
// start would eat as a group or the negation.
func isCustomTargetText(text string) bool {
	if text == "" || text == "any" || text == "me" || text == "me6" || text == "not" ||
		text[0] == '`' || text[0] == '{' || strings.IndexByte(text, '#') >= 0 {
		return false
	}
	if _, _, ok := tableName(text); ok {
		return false
	}
	if isNetwork6Text(text) || isNetwork4Text(text) || isHostnameText(text) {
		return false
	}
	_, rest := takeWhile(text, isTargetByte)
	return rest == ""
}

// appendPorts writes one port section: a comma-joined list under a single
// negation, a destination first member named after an option keyword
// rejected because the option probe eats it.
func appendPorts(dst []byte, matches []PortMatch, side bodySide) ([]byte, error) {
	for idx := range matches {
		if matches[idx].Neg != matches[0].Neg {
			return dst, ErrInconsistentNegation
		}
	}
	if side == destinationSide &&
		(matchesOptionKeyword(matches[0].Lo.Name) || matchesArgumentOption(matches[0].Lo.Name)) {
		return dst, ErrInvalidName
	}
	if matches[0].Neg {
		dst = append(dst, "not "...)
	}
	for idx := range matches {
		if idx > 0 {
			dst = append(dst, ',')
		}
		var err error
		forceRange := idx == 0 && bodyPortNeedsRange(matches[idx].Lo, side)
		if dst, err = appendPortMatch(dst, matches[idx], forceRange); err != nil {
			return dst, err
		}
	}
	return dst, nil
}

func matchesOptionKeyword(text string) bool {
	_, _, ok := keywordOption(text)
	return ok
}

// appendPortMatch writes one range, a single port without the dash unless
// its name needs the dash to stay a port.
func appendPortMatch(dst []byte, match PortMatch, forceRange bool) ([]byte, error) {
	var err error
	if dst, err = appendPort(dst, match.Lo); err != nil {
		return dst, err
	}
	if match.Lo == match.Hi && !forceRange {
		return dst, nil
	}
	if strings.HasSuffix(match.Lo.Name, `\`) {
		return dst, ErrInvalidName
	}
	dst = append(dst, '-')
	return appendPort(dst, match.Hi)
}

func bodyPortNeedsRange(port Port, side bodySide) bool {
	if port.Name == "not" || port.Name == "to" {
		return true
	}
	return side == destinationSide &&
		(matchesOptionKeyword(port.Name) || matchesArgumentOption(port.Name))
}

func matchesArgumentOption(text string) bool {
	kind, _ := argumentOption(text)
	return kind != 0
}

// appendPort writes a port by number or by name with its escapes, rejecting
// a name the section would not read back as that name.
func appendPort(dst []byte, port Port) ([]byte, error) {
	if port.Name == "" {
		return strconv.AppendUint(dst, uint64(port.Number), 10), nil
	}
	if port.Number != 0 {
		return dst, ErrUnexpectedBody
	}
	if !isPortNameText(port.Name) {
		return dst, ErrInvalidName
	}
	return append(dst, port.Name...), nil
}

// isPortNameText reports whether text reads back as a service name: port
// bytes with a backslash before a dash or at the end, and not one plain
// number.
func isPortNameText(text string) bool {
	idx := 0
	for idx < len(text) {
		switch c := text[idx]; {
		case isPortByte(c):
			idx++
		case c == '\\':
			if idx+1 < len(text) && text[idx+1] != '-' {
				return false
			}
			idx += 2
		default:
			return false
		}
	}
	if _, afterNumber, kind := parseU16(text); kind == 0 && afterNumber == "" {
		return false
	}
	return text != ""
}

// appendOptions writes the or-blocks of the options, a block of several match
// patterns braced and the members of a list joined by commas.
//
// A leading native custom option is braced against header and legacy grammar
// probes. Exact `not` stays bare because braces would turn it into negation.
func appendOptions(
	dst []byte,
	opts []Opt,
	custom CustomOptAppender,
	protectFirstCustom bool,
) ([]byte, error) {
	if err := validateOptionPlaces(opts); err != nil {
		return dst, err
	}
	commentIndex := len(opts)
	if commentIndex > 0 {
		comment := &opts[commentIndex-1]
		if comment.Kind == OptComment &&
			(commentIndex == 1 || opts[commentIndex-2].Block != comment.Block) {
			commentIndex--
		}
	}
	options := opts[:commentIndex]
	if err := validateStateOptions(options); err != nil {
		return dst, err
	}
	lastCustomIsNot := false
	for idx := 0; idx < len(options); {
		opt := options[idx]
		next := nextOptionPattern(options, idx)
		lastInBlock := next == len(options) || options[next].Block != opt.Block
		inGroup := opt.Pattern > 0 || !lastInBlock
		customSyntax := opt.Kind == OptCustom || opt.Kind == OptComment
		protectCustom := protectFirstCustom && idx == 0 && customSyntax && !inGroup
		switch {
		case opt.Pattern > 0:
			dst = append(dst, " or "...)
		case inGroup:
			if idx > 0 {
				dst = append(dst, ' ')
			}
			dst = append(dst, "{ "...)
		case idx > 0:
			dst = append(dst, ' ')
		}
		var err error
		customStart := len(dst)
		if dst, err = appendOpt(dst, opt, custom, customSyntax); err != nil {
			return dst, err
		}
		customIsNot := customSyntax && !opt.Neg && isExactNot(dst[customStart:])
		if customIsNot && (inGroup || next != len(options)) {
			return dst, ErrInvalidName
		}
		lastCustomIsNot = customIsNot
		if protectCustom && !isExactNot(dst[customStart:]) {
			customEnd := len(dst)
			dst = append(dst, 0, 0, ' ', '}')
			copy(dst[customStart+2:customEnd+2], dst[customStart:customEnd])
			dst[customStart], dst[customStart+1] = '{', ' '
		}
		for member := idx + 1; member < next; member++ {
			if err = validateListMember(opt, options[member]); err != nil {
				return dst, err
			}
			dst = append(dst, ',')
			if dst, err = appendPortMatch(dst, PortMatch{
				Lo: options[member].Ports.Lo,
				Hi: options[member].Ports.Hi,
			}, false); err != nil {
				return dst, err
			}
		}
		if inGroup && lastInBlock {
			dst = append(dst, " }"...)
		}
		idx = next
	}
	if commentIndex < len(opts) {
		comment := opts[commentIndex]
		if len(options) > 0 {
			if lastCustomIsNot {
				if comment.Neg {
					return dst, ErrInvalidName
				}
			} else {
				dst = append(dst, ' ')
			}
		}
		return appendOpt(dst, comment, custom, false)
	}
	return dst, nil
}

// validateOptionPlaces requires the places the parser gives: the or-blocks
// numbered in order from zero, and the match patterns of every block too.
func validateOptionPlaces(opts []Opt) error {
	for idx := range opts {
		opt := &opts[idx]
		if idx == 0 {
			if opt.Block != 0 || opt.Pattern != 0 {
				return ErrBrokenOrChain
			}
			continue
		}
		prev := &opts[idx-1]
		sameBlock := opt.Block == prev.Block &&
			(opt.Pattern == prev.Pattern || opt.Pattern == prev.Pattern+1)
		nextBlock := opt.Block == prev.Block+1 && opt.Pattern == 0
		if !sameBlock && !nextBlock {
			return ErrBrokenOrChain
		}
	}
	return nil
}

// nextOptionPattern returns the index past the match pattern starting at idx.
func nextOptionPattern(opts []Opt, idx int) int {
	head := &opts[idx]
	idx++
	for idx < len(opts) && opts[idx].Block == head.Block && opts[idx].Pattern == head.Pattern {
		idx++
	}
	return idx
}

// validateListMember checks a member after the first of a match pattern,
// which only a port list has.
func validateListMember(head, member Opt) error {
	if head.Kind != OptSourcePort && head.Kind != OptDestinationPort || member.Kind != head.Kind {
		return ErrBrokenOrChain
	}
	if member.Neg != head.Neg {
		return ErrInconsistentNegation
	}
	return requireZeroOptArgs(member)
}

// validateStateOptions enforces the parser's placement and uniqueness rules for keep-state.
func validateStateOptions(opts []Opt) error {
	seen := false
	for idx := range opts {
		opt := &opts[idx]
		if opt.Kind != OptKeepState {
			continue
		}
		if opt.Pattern > 0 || idx+1 < len(opts) && opts[idx+1].Block == opt.Block {
			return ErrDynamicStateInGroup
		}
		if seen {
			return ErrDuplicateDynamicState
		}
		seen = true
	}
	return nil
}

// appendOpt writes one option with its negation and the argument of its
// kind.
func appendOpt(dst []byte, opt Opt, custom CustomOptAppender, customSyntax bool) ([]byte, error) {
	if opt.Neg {
		dst = append(dst, "not "...)
	}
	if customSyntax {
		if custom == nil {
			return dst, ErrMissingCustomOptAppender
		}
		buf, err := custom(dst, opt)
		if err != nil {
			return dst, err
		}
		if len(buf) <= len(dst) || hasLineDelimiter(buf[len(dst):]) ||
			startsReservedOptionSyntax(buf[len(dst):]) {
			return dst, ErrInvalidName
		}
		return buf, nil
	}
	if err := requireZeroOptArgs(opt); err != nil {
		return dst, err
	}
	switch opt.Kind {
	case OptComment:
		if err := validateCommentOptionText(opt.Text); err != nil {
			return dst, err
		}
		dst = append(dst, "//"...)
		return append(dst, opt.Text...), nil
	case OptSourcePort, OptDestinationPort:
		dst = append(dst, opt.Kind.String()...)
		dst = append(dst, ' ')
		return appendPortMatch(dst, PortMatch{Lo: opt.Ports.Lo, Hi: opt.Ports.Hi}, false)
	case OptICMPTypes, OptICMP6Types:
		return appendTypes(dst, opt)
	case OptKeepState:
		dst = append(dst, "keep-state"...)
		if opt.Text != "" {
			if !isTokenText(opt.Text) {
				return dst, ErrInvalidName
			}
			dst = append(dst, " :"...)
			dst = append(dst, opt.Text...)
		}
		return dst, nil
	case OptProto:
		return appendProtoOpt(dst, opt.Proto)
	case OptTCPFlags:
		return appendTCPFlags(dst, opt)
	case OptVia:
		return appendVia(dst, opt)
	case OptDiverted, OptEstablished, OptFrag, OptIn, OptOut, OptAntiSpoof:
		return append(dst, opt.Kind.String()...), nil
	default:
		return dst, ErrUnknownOptionKind
	}
}

func hasLineDelimiter(text []byte) bool {
	for idx := range text {
		if text[idx] == '\n' || text[idx] == '#' {
			return true
		}
	}
	return false
}

func startsReservedOptionSyntax(text []byte) bool {
	option := string(text)
	if hasPrefix(option, "//") || option[0] == '{' {
		return true
	}
	if _, ok := notWS1(option); ok {
		return true
	}
	if kind, _ := argumentOption(option); kind != 0 {
		return true
	}
	_, _, ok := keywordOption(option)
	return ok
}

// requireZeroOptArgs rejects the argument fields an option kind does not
// take, which the parser never fills.
func requireZeroOptArgs(opt Opt) error {
	if opt.Kind != OptKeepState && opt.Kind != OptComment && opt.Text != "" {
		return ErrUnexpectedBody
	}
	if opt.Arg != "" {
		return ErrUnexpectedBody
	}
	if opt.Kind != OptSourcePort && opt.Kind != OptDestinationPort && opt.Ports != (PortRange{}) {
		return ErrUnexpectedBody
	}
	if opt.Kind != OptProto && opt.Proto != (Proto{}) {
		return ErrUnexpectedBody
	}
	if opt.Kind != OptICMPTypes && opt.Kind != OptICMP6Types && !opt.Types.IsEmpty() {
		return ErrUnexpectedBody
	}
	if opt.Kind != OptTCPFlags && opt.TCPFlags != (TCPFlags{}) {
		return ErrUnexpectedBody
	}
	if opt.Kind != OptVia && opt.Via != (Via{}) {
		return ErrUnexpectedBody
	}
	return nil
}

// appendProtoOpt writes the protocol after the proto keyword, which keeps
// names the body would classify as IP versions.
func appendProtoOpt(dst []byte, proto Proto) ([]byte, error) {
	dst = append(dst, "proto "...)
	if proto.Name == "" {
		if proto.Number == 0 {
			return dst, ErrInvalidName
		}
		return strconv.AppendUint(dst, uint64(proto.Number), 10), nil
	}
	if !isProtoNameText(proto.Name) || proto.Number != 0 {
		return dst, ErrInvalidName
	}
	return append(dst, proto.Name...), nil
}

// appendTypes writes the icmptypes or icmp6types set in ascending numeric
// order, a type unknown to the kind rejected.
func appendTypes(dst []byte, opt Opt) ([]byte, error) {
	if opt.Types.IsEmpty() {
		return dst, ErrEmptyTypeSet
	}
	dst = append(dst, opt.Kind.String()...)
	dst = append(dst, ' ')
	first := true
	for ty := range 256 {
		if !opt.Types.Has(uint8(ty)) {
			continue
		}
		if !icmpTypeInRange(opt.Kind, uint8(ty)) {
			return dst, unknownTypeKind(opt.Kind)
		}
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = strconv.AppendUint(dst, uint64(ty), 10)
	}
	return dst, nil
}

// tcpFlagsAll is every TCP flag the tcpflags argument can name.
const tcpFlagsAll = TCPFin | TCPSyn | TCPRst | TCPPsh | TCPAck | TCPUrg

// appendTCPFlags writes every requirement in canonical order, a flag that
// must be clear carrying a bang.
func appendTCPFlags(dst []byte, opt Opt) ([]byte, error) {
	flags := opt.TCPFlags
	if flags.Set|flags.Clear == 0 || flags.Set|flags.Clear > tcpFlagsAll {
		return dst, ErrInvalidTCPFlags
	}
	dst = append(dst, "tcpflags "...)
	first := true
	for idx := range tcpFlagNames {
		flag := tcpFlagNames[idx].flag
		if flag&flags.Set != 0 {
			if !first {
				dst = append(dst, ',')
			}
			first = false
			dst = append(dst, tcpFlagNames[idx].name...)
		}
		if flag&flags.Clear != 0 {
			if !first {
				dst = append(dst, ',')
			}
			first = false
			dst = append(dst, '!')
			dst = append(dst, tcpFlagNames[idx].name...)
		}
	}
	return dst, nil
}

// appendVia writes the via argument: an interface name, a mask or a table
// lookup.
func appendVia(dst []byte, opt Opt) ([]byte, error) {
	via := opt.Via
	if via.Kind != ViaTable && via.Value != "" {
		return dst, ErrUnexpectedBody
	}
	if via.Kind != ViaTable && strings.HasPrefix(via.Name, "table(") {
		return dst, ErrInvalidName
	}
	switch via.Kind {
	case ViaExact:
		if !isIfNameText(via.Name) || strings.ContainsAny(via.Name, "*?[]") {
			return dst, ErrInvalidName
		}
	case ViaMask:
		if !isIfNameText(via.Name) || !strings.ContainsAny(via.Name, "*?[]") {
			return dst, ErrInvalidName
		}
	case ViaTable:
		if !isViaTableName(via.Name) {
			return dst, ErrInvalidName
		}
		if via.Value != "" && !isTableValueText(via.Value) {
			return dst, ErrInvalidName
		}
		dst = append(dst, "via table("...)
		dst = append(dst, via.Name...)
		if via.Value != "" {
			dst = append(dst, ',')
			dst = append(dst, via.Value...)
		}
		return append(dst, ')'), nil
	default:
		return dst, ErrUnknownViaKind
	}
	dst = append(dst, "via "...)
	return append(dst, via.Name...), nil
}

// isIfNameText reports whether text is one interface-name token.
func isIfNameText(text string) bool {
	if text == "" || strings.IndexByte(text, '#') >= 0 {
		return false
	}
	_, rest := takeWhile(text, isIfNameByte)
	return rest == ""
}

// isViaTableName reports whether text reads back as the name inside a via
// table lookup.
func isViaTableName(text string) bool {
	if text == "" || strings.IndexByte(text, '#') >= 0 {
		return false
	}
	_, rest := takeWhile(text, isTableNameByte)
	return rest == ""
}

// isTableValueText reports whether text reads back as the value inside a
// table lookup, of a target or of via.
func isTableValueText(text string) bool {
	if text == "" || strings.IndexByte(text, '#') >= 0 {
		return false
	}
	_, rest := takeWhile(text, isTableValueByte)
	return rest == ""
}

// appendTable writes a table command: create with its optional type, add
// with its key and optional value.
func appendTable(dst []byte, table Table) ([]byte, error) {
	if !isTokenText(table.Name) {
		return dst, ErrInvalidName
	}
	dst = append(dst, "table "...)
	dst = append(dst, table.Name...)
	switch table.Kind {
	case TableCreate:
		if table.Key != (TableKey{}) || table.Value != "" {
			return dst, ErrUnexpectedBody
		}
		dst = append(dst, " create"...)
		if table.Type != TableTypeUnset {
			keyword, err := tableTypeText(table.Type)
			if err != nil {
				return dst, err
			}
			dst = append(dst, " type "...)
			dst = append(dst, keyword...)
		}
		return dst, nil
	case TableAdd:
		if table.Type != TableTypeUnset {
			return dst, ErrUnexpectedBody
		}
		if table.Value != "" && !isTokenText(table.Value) {
			return dst, ErrInvalidName
		}
		dst = append(dst, " add "...)
		var err error
		if dst, err = appendTableKey(dst, table.Key); err != nil {
			return dst, err
		}
		if table.Value != "" {
			dst = append(dst, ' ')
			dst = append(dst, table.Value...)
		}
		return dst, nil
	default:
		return dst, ErrUnknownTableKind
	}
}

// tableTypeText returns the keyword of a table type.
func tableTypeText(tableType TableType) (string, error) {
	switch tableType {
	case TableTypeAddr:
		return "addr", nil
	case TableTypeIface:
		return "iface", nil
	case TableTypeNumber:
		return "number", nil
	case TableTypeFlow:
		return "flow", nil
	case TableTypeMAC:
		return "mac", nil
	default:
		return "", ErrUnknownTableType
	}
}

// appendTableKey writes the key of a table entry by its classified shape.
func appendTableKey(dst []byte, key TableKey) ([]byte, error) {
	switch key.Kind {
	case TableKeyNetwork4:
		if !isNetwork4Text(key.Text) {
			return dst, ErrInvalidName
		}
	case TableKeyNetwork6:
		if !isNetwork6Text(key.Text) {
			return dst, ErrInvalidName
		}
	case TableKeyHostname:
		if !isHostnameText(key.Text) {
			return dst, ErrInvalidName
		}
	case TableKeyName:
		if isNetwork4Text(key.Text) || isNetwork6Text(key.Text) || isHostnameText(key.Text) ||
			!isTokenText(key.Text) {
			return dst, ErrInvalidName
		}
	default:
		return dst, ErrUnknownTableKeyKind
	}
	return append(dst, key.Text...), nil
}
