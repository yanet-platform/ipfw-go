package ipfw

import (
	"io"
	"iter"
	"strings"
)

// Parser reads a ruleset line by line.
type Parser struct {
	rest string
	line int
}

// ParserOption configures a Parser.
type ParserOption func(*Parser)

// NewParser returns a parser over src.
func NewParser(src string, options ...ParserOption) *Parser {
	parser := &Parser{rest: src}
	for _, option := range options {
		option(parser)
	}
	return parser
}

// Reset makes the parser read src from its first line.
func (m *Parser) Reset(src string) {
	m.rest = src
	m.line = 0
}

// Next parses the next line, pushing the rule body into state.
//
// It returns io.EOF once the input is exhausted and a *ParseError when the
// line does not parse, in which case the offending line is skipped.
func (m *Parser) Next(state State) (Record, error) {
	if m.rest == "" {
		return Record{}, io.EOF
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

func (m *Parser) parseInstruction(s string, state State) (Instruction, string, fail) {
	return Instruction{}, s, fail{Kind: ErrExpectedAction, At: s}
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
func (m *Parser) All(state State) iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		for {
			record, err := m.Next(state)
			if err == io.EOF {
				return
			}
			if err != nil {
				yield(Record{}, err)
				return
			}
			if !yield(record, nil) {
				return
			}
		}
	}
}

// ParseLine parses exactly one line, with or without its trailing newline.
// An empty input is an empty line.
func ParseLine(line string, state State, options ...ParserOption) (Record, error) {
	if len(options) > 0 {
		return parseSingleLine(NewParser(line, options...), state)
	}
	parser := Parser{rest: line}
	return parseSingleLine(&parser, state)
}

func parseSingleLine(parser *Parser, state State) (Record, error) {
	record, err := parser.Next(state)
	if err == io.EOF {
		return Record{Line: 1, Kind: RecordEmpty}, nil
	}
	if err != nil {
		return Record{}, err
	}
	if parser.rest != "" {
		return Record{}, &ParseError{Kind: ErrExpectedNewlineOrEOF, Line: 1, Column: len(record.Text), Text: record.Text}
	}
	return record, nil
}

// RecordKind is what a line holds.
type RecordKind uint8

// The record kinds.
const (
	RecordEmpty RecordKind = iota
	RecordComment
	RecordInstruction
	RecordTable
	RecordLabel
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
