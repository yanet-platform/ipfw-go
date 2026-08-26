package ipfw

import (
	"iter"
	"strings"
)

// Parser reads a ruleset line by line.
type Parser struct {
	rest string
	line int
	opts parserOptions
}

// parserOptions is what a ParserOption configures. Hooks will be its fields.
type parserOptions struct{}

func newParserOptions() parserOptions {
	return parserOptions{}
}

// ParserOption configures a Parser, see the With functions.
type ParserOption func(*parserOptions)

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
// Once the input is exhausted it returns a record of kind RecordEOF. A line
// that does not parse is skipped as a whole and reported as a *ParseError,
// a concrete pointer to compare with nil before storing it in an error.
func (m *Parser) Next(state State) (Record, *ParseError) {
	if m.rest == "" {
		return Record{Kind: RecordEOF}, nil
	}
	m.line++
	text := ws0(m.rest)
	record, rest, err := m.parseLine(text, state)
	if err.Failed() {
		lineText := physicalLine(text)
		m.rest = afterLine(text)
		column := min(max(len(text)-len(err.At), 0), len(lineText))
		return Record{}, &ParseError{Kind: err.Kind, Err: err.Err, Line: m.line, Column: column, Text: lineText}
	}
	record.Line = m.line
	record.Text = trimRightSpace(text[:len(text)-len(rest)])
	m.rest = rest
	return record, nil
}

// parseLine parses one line starting at its first non-blank byte and returns
// the input after the line's newline.
func (m *Parser) parseLine(text string, state State) (Record, string, fail) {
	var record Record
	s := text
	commanded := false
	var err fail
	if rest, ok := prefix(s, "add"); ok {
		rest, ok = ws1(rest)
		if !ok {
			return record, text, fail{Kind: ErrExpectedWhitespace, At: rest}
		}
		record.Instruction, rest, err = m.parseInstruction(rest, state)
		if err.Failed() {
			return record, text, err
		}
		record.Kind = RecordInstruction
		s, commanded = rest, true
	} else if rest, ok := prefix(s, "table"); ok {
		rest, ok = ws1(rest)
		if !ok {
			return record, text, fail{Kind: ErrExpectedWhitespace, At: rest}
		}
		record.Table, rest, err = m.parseTable(rest)
		if err.Failed() {
			return record, text, err
		}
		record.Kind = RecordTable
		s, commanded = rest, true
	} else if rest, ok := prefix(s, ":"); ok {
		record.Label, rest = token(rest)
		if record.Label == "" {
			return record, text, fail{Kind: ErrExpectedToken, At: rest}
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
		return record, rest, fail{}
	}
	if s == "" {
		return record, s, fail{}
	}
	if record.Kind == RecordEmpty {
		return record, text, fail{Kind: ErrExpectedLine, At: s}
	}
	return record, text, fail{Kind: ErrExpectedNewlineOrEOF, At: s}
}

// parseInstruction parses `[NUM] ACTION … [// comment]` after `add `.
func (m *Parser) parseInstruction(s string, state State) (Instruction, string, fail) {
	var instruction Instruction
	input := s
	if num, afterNum, kind := parseU32(s); kind == 0 {
		if afterWS, ok := ws1(afterNum); ok {
			instruction.Num, s = num, afterWS
		}
	}
	action, rest, err := parseAction(s)
	if err.Failed() {
		return instruction, input, err
	}
	instruction.Action = action
	if action.Kind == ActionCheckState {
		return instruction, rest, fail{}
	}
	rest, ok := ws1(rest)
	if !ok {
		return instruction, input, fail{Kind: ErrExpectedWhitespace, At: rest}
	}
	rest, err = m.parseBody(rest, state)
	if err.Failed() {
		return instruction, input, err
	}
	instruction.InlineComment, rest = parseInlineComment(rest)
	return instruction, rest, fail{}
}

func (m *Parser) parseBody(s string, state State) (string, fail) {
	return s, fail{Kind: ErrExpectedEitherIPOrProto, At: s}
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

func (m *Parser) parseTable(s string) (Table, string, fail) {
	return Table{}, s, fail{Kind: ErrExpectedTableCommand, At: s}
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
func (m *Parser) All(state State) iter.Seq2[Record, *ParseError] {
	return func(yield func(Record, *ParseError) bool) {
		for {
			record, err := m.Next(state)
			if err != nil {
				yield(Record{}, err)
				return
			}
			if record.Kind == RecordEOF || !yield(record, nil) {
				return
			}
		}
	}
}

// ParseLine parses exactly one line, with or without its trailing newline.
// An empty input is an empty line.
func ParseLine(line string, state State, options ...ParserOption) (Record, *ParseError) {
	if len(options) > 0 {
		return parseSingleLine(NewParser(line, options...), state)
	}
	parser := Parser{rest: line, opts: newParserOptions()}
	return parseSingleLine(&parser, state)
}

func parseSingleLine(parser *Parser, state State) (Record, *ParseError) {
	record, err := parser.Next(state)
	if err != nil {
		return Record{}, err
	}
	if record.Kind == RecordEOF {
		return Record{Line: 1, Kind: RecordEmpty}, nil
	}
	if parser.rest != "" {
		return Record{}, &ParseError{Kind: ErrExpectedNewlineOrEOF, Line: 1, Column: len(record.Text), Text: record.Text}
	}
	return record, nil
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
	// Tag is the `tag` number, 0 when absent.
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
