package ipfw

import (
	"iter"
	"strings"
)

// parserOptions is what a ParserOption configures. Hooks will be its fields.
type parserOptions struct{}

func newParserOptions() parserOptions {
	return parserOptions{}
}

// ParserOption configures a Parser, see the With functions.
type ParserOption func(*parserOptions)

// Parser reads a ruleset line by line.
type Parser struct {
	rest   string
	line   int
	opts   parserOptions
	record Record
}

// NewParser returns a parser over src.
func NewParser(src string, options ...ParserOption) *Parser {
	opts := newParserOptions()
	for _, option := range options {
		option(&opts)
	}
	return &Parser{rest: src, opts: opts}
}

// Reset makes the parser read src from its first line.
func (m *Parser) Reset(src string) {
	m.rest = src
	m.line = 0
}

// Next parses the next line, pushing the rule body into state.
//
// The record belongs to the parser and is overwritten by the next call to
// Next or Reset, copy it to keep it. Once the input is exhausted the record
// is of kind RecordEOF. A line that does not parse is skipped as a whole and
// reported as a *ParseError, a concrete pointer to compare with nil before
// storing it in an error.
func (m *Parser) Next(state State) (*Record, *ParseError) {
	m.record = Record{}
	if m.rest == "" {
		m.record.Kind = RecordEOF
		return &m.record, nil
	}
	m.line++
	text := ws0(m.rest)
	rest, err := m.parseLine(text, state)
	if err.Failed() {
		lineText := physicalLine(text)
		m.rest = afterLine(text)
		column := min(max(len(text)-len(err.At), 0), len(lineText))
		return nil, &ParseError{
			Kind:   err.Kind,
			Err:    err.Err,
			Line:   m.line,
			Column: column,
			Text:   lineText,
		}
	}
	m.record.Line = m.line
	m.record.Text = trimRightSpace(text[:len(text)-len(rest)])
	m.rest = rest
	return &m.record, nil
}

// parseLine parses one line starting at its first non-blank byte into the
// parser's record and returns the input after the line's newline.
func (m *Parser) parseLine(text string, state State) (string, fail) {
	record := &m.record
	s := text
	commanded := false
	var err fail
	if rest, ok := prefix(s, "add"); ok {
		rest, ok = ws1(rest)
		if !ok {
			return text, fail{Kind: ErrExpectedWhitespace, At: rest}
		}
		rest, err = m.parseInstruction(rest, state, &record.Instruction)
		if err.Failed() {
			return text, err
		}
		record.Kind = RecordInstruction
		s, commanded = rest, true
	} else if rest, ok := prefix(s, "table"); ok {
		rest, ok = ws1(rest)
		if !ok {
			return text, fail{Kind: ErrExpectedWhitespace, At: rest}
		}
		record.Table, rest, err = parseTable(rest)
		if err.Failed() {
			return text, err
		}
		record.Kind = RecordTable
		s, commanded = rest, true
	} else if rest, ok := prefix(s, ":"); ok {
		record.Label, rest = token(rest)
		if record.Label == "" {
			return text, fail{Kind: ErrExpectedToken, At: rest}
		}
		record.Kind = RecordLabel
		s, commanded = rest, true
	}
	s = ws0(s)
	if !commanded {
		if rest, ok := prefix(s, "#"); ok {
			record.Comment, rest = takeWhile(rest, isNotNewline)
			record.Kind = RecordComment
			s = rest
		}
	}
	if rest, ok := prefix(s, "\n"); ok {
		return rest, fail{}
	}
	if s == "" {
		return s, fail{}
	}
	if record.Kind == RecordEmpty {
		return text, fail{Kind: ErrExpectedLine, At: s}
	}
	return text, fail{Kind: ErrExpectedNewlineOrEOF, At: s}
}

// parseInstruction parses `[NUM] ACTION … [// comment]` after `add ` into
// instruction, which may be partially written when it fails.
func (m *Parser) parseInstruction(s string, state State, instruction *Instruction) (string, fail) {
	input := s
	if num, afterNum, kind := parseU32(s); kind == 0 {
		if afterWS, ok := ws1(afterNum); ok {
			instruction.Num, s = num, afterWS
		}
	}
	rest, err := parseAction(s, &instruction.Action)
	if err.Failed() {
		return input, err
	}
	instruction.Log, rest, err = parseLog(rest)
	if err.Failed() {
		return input, err
	}
	instruction.Tag, rest, err = parseTag(rest)
	if err.Failed() {
		return input, err
	}
	if instruction.Action.Kind == ActionCheckState {
		return rest, fail{}
	}
	rest, ok := ws1(rest)
	if !ok {
		return input, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	rest, err = m.parseBody(rest, state)
	if err.Failed() {
		return input, err
	}
	instruction.InlineComment, rest = parseInlineComment(rest)
	return rest, fail{}
}

// parseLog parses the optional ` log [logamount N]` after the action, the
// input coming back untouched when the log keyword is absent.
//
// The keywords match by prefix, so `logamount` without `log` before it is
// read as `log`.
func parseLog(s string) (Log, string, fail) {
	buf, ok := ws1Keyword(s, "log")
	if !ok {
		return Log{}, s, fail{}
	}
	rest := buf
	if buf, ok = ws1Keyword(buf, "logamount"); !ok {
		return Log{Enabled: true}, rest, fail{}
	}
	if buf, ok = ws1(buf); !ok {
		return Log{}, s, fail{Kind: ErrExpectedWhitespace, At: buf}
	}
	amount, buf, kind := parseU32(buf)
	if kind != 0 {
		return Log{}, s, fail{Kind: kind, At: buf}
	}
	return Log{Enabled: true, HasAmount: true, Amount: amount}, buf, fail{}
}

// parseTag parses the optional ` tag N` after the log part, the input
// coming back untouched when the keyword is absent.
func parseTag(s string) (uint32, string, fail) {
	buf, ok := ws1Keyword(s, "tag")
	if !ok {
		return 0, s, fail{}
	}
	if buf, ok = ws1(buf); !ok {
		return 0, s, fail{Kind: ErrExpectedWhitespace, At: buf}
	}
	tag, buf, kind := parseU32(buf)
	if kind != 0 {
		return 0, s, fail{Kind: kind, At: buf}
	}
	return tag, buf, fail{}
}

// bodySide is the end of the body a target or a port belongs to, which
// decides the State callback it goes to.
type bodySide uint8

const (
	sourceSide bodySide = iota
	destinationSide
)

// parseBody parses `PROTO from SRC [PORT] to DST [PORT] [OPTIONS]`.
func (m *Parser) parseBody(s string, state State) (string, fail) {
	rest, err := parseProtocols(s, state)
	if err.Failed() {
		return s, err
	}
	rest, ok := ws1(rest)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	rest, ok = prefix(rest, "from")
	if !ok {
		return s, fail{Kind: ErrExpectedFrom, At: rest}
	}
	rest, ok = ws1(rest)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	rest, err = parseTargets(rest, state, sourceSide)
	if err.Failed() {
		return s, err
	}
	rest, ok = ws1(rest)
	if !ok {
		return s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	// Only `to` followed by whitespace ends the source part, so a port such
	// as `topx` or `notify` is not mistaken for a keyword.
	if buf, ok := keywordWS1(rest, "to"); ok {
		rest = buf
	} else {
		rest, err = parsePorts(rest, state, sourceSide)
		if err.Failed() {
			return s, err
		}
		rest, ok = ws1(rest)
		if !ok {
			return s, fail{Kind: ErrExpectedWhitespace, At: rest}
		}
		rest, ok = prefix(rest, "to")
		if !ok {
			return s, fail{Kind: ErrExpectedPrefix, At: rest}
		}
		rest, ok = ws1(rest)
		if !ok {
			return s, fail{Kind: ErrExpectedWhitespace, At: rest}
		}
	}
	rest, err = parseTargets(rest, state, destinationSide)
	if err.Failed() {
		return s, err
	}
	// Options come before destination ports, tried first over a discarding
	// state so that a rejected attempt emits nothing.
	//
	// `to any established` is an option, `to any domain` a port and `to any
	// 22 established` both. A failed port attempt leaves the input where the
	// destination ended.
	if buf, ok := ws1(rest); ok {
		if _, err = parseOptions(buf, DiscardState{}, nil); !err.Failed() {
			return parseOptions(buf, state, nil)
		}
		if buf, err = parsePorts(buf, state, destinationSide); !err.Failed() {
			rest = buf
		}
	}
	if buf, ok := ws1(rest); ok {
		if rest, err = parseOptions(buf, state, nil); err.Failed() {
			return s, err
		}
	}
	return rest, fail{}
}

// parseInlineComment returns the raw text after `//`, leading whitespace
// before the slashes skipped, or the untouched input when there is none.
func parseInlineComment(s string) (string, string) {
	rest, ok := prefix(ws0(s), "//")
	if !ok {
		return "", s
	}
	return takeWhile(rest, isNotNewline)
}

// parseTable parses `NAME create|add …` after `table `.
func parseTable(s string) (Table, string, fail) {
	name, rest := token(s)
	if name == "" {
		return Table{}, s, fail{Kind: ErrExpectedToken, At: s}
	}
	rest, ok := ws1(rest)
	if !ok {
		return Table{}, s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	table := Table{Name: name}
	var err fail
	switch {
	case strings.HasPrefix(rest, "create"):
		table.Kind = TableCreate
		table.Type, rest, err = parseTableCreate(rest[len("create"):])
	default:
		return Table{}, s, fail{Kind: ErrExpectedTableCommand, At: rest}
	}
	if err.Failed() {
		return Table{}, s, err
	}
	return table, rest, fail{}
}

// parseTableCreate parses the options after `create`, the whitespace after
// the keyword being required even with none, and the last `type` winning.
func parseTableCreate(s string) (TableType, string, fail) {
	rest, ok := ws1(s)
	if !ok {
		return TableTypeUnset, s, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	tableType := TableTypeUnset
	buf, ok := prefix(rest, "type")
	for ok {
		var kind ErrorKind
		if buf, ok = ws1(buf); !ok {
			return TableTypeUnset, s, fail{Kind: ErrExpectedWhitespace, At: buf}
		}
		if tableType, buf, kind = parseTableType(buf); kind != 0 {
			return TableTypeUnset, s, fail{Kind: kind, At: buf}
		}
		rest = buf
		buf, ok = ws1Keyword(rest, "type")
	}
	return tableType, rest, fail{}
}

// tableTypeNames are the table types by keyword, in the order tried.
var tableTypeNames = [...]struct {
	name      string
	tableType TableType
}{
	{"addr", TableTypeAddr},
	{"iface", TableTypeIface},
	{"number", TableTypeNumber},
	{"flow", TableTypeFlow},
	{"mac", TableTypeMAC},
}

// parseTableType tells a table type by its keyword, matching by prefix.
func parseTableType(s string) (TableType, string, ErrorKind) {
	for idx := range tableTypeNames {
		if rest, ok := prefix(s, tableTypeNames[idx].name); ok {
			return tableTypeNames[idx].tableType, rest, 0
		}
	}
	return TableTypeUnset, s, ErrExpectedTableType
}

func isNotNewline(c byte) bool {
	return c != '\n'
}

func physicalLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	return trimRightSpace(line)
}

func afterLine(text string) string {
	_, after, _ := strings.Cut(text, "\n")
	return after
}

func trimRightSpace(s string) string {
	end := len(s)
	for end > 0 && isASCIISpace(s[end-1]) {
		end--
	}
	return s[:end]
}

// All iterates over the records until the input ends or a line fails, the
// failure being the last value yielded.
func (m *Parser) All(state State) iter.Seq2[*Record, *ParseError] {
	return func(yield func(*Record, *ParseError) bool) {
		for {
			record, err := m.Next(state)
			if err != nil {
				yield(nil, err)
				return
			}
			if record.Kind == RecordEOF || !yield(record, nil) {
				return
			}
		}
	}
}

// RecordKind is what a line holds.
type RecordKind uint8

// The record kinds. RecordEOF is returned once the input is exhausted.
const (
	RecordEmpty RecordKind = iota
	RecordComment
	RecordInstruction
	RecordTable
	RecordLabel
	RecordEOF
)

// Record is one parsed line.
type Record struct {
	// Line is 1-based.
	Line int
	// Text is the line without leading and trailing whitespace.
	Text string
	// Kind is what the line holds.
	Kind RecordKind
	// Comment is the text after `#`, leading space included.
	Comment string
	// Instruction is set for an add rule.
	Instruction Instruction
	// Table is set for a table command.
	Table Table
	// Label is the name without the leading colon.
	Label string
}

// Instruction is the header of an `add` rule, the body going to the State.
type Instruction struct {
	// Num is the explicit rule number, 0 when absent.
	Num uint32
	// Action is the rule action.
	Action Action
	// Log is the logging part.
	Log Log
	// Tag is the `tag` number, 0 when absent, so a `tag 0` reads as none.
	Tag uint32
	// InlineComment is the raw text after `//`, empty when absent.
	InlineComment string
}

// Log is the `log [logamount N]` part of a rule.
type Log struct {
	// Enabled is the `log` keyword.
	Enabled bool
	// HasAmount is the `logamount` keyword.
	HasAmount bool
	// Amount is the logamount value.
	Amount uint32
}
