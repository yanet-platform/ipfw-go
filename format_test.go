package ipfw_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/ipfw-go"
)

// parseT is what the parse and format helpers need from a *testing.T and a
// *rapid.T.
type parseT interface {
	FailNow()
	Errorf(format string, args ...any)
}

// parseOne parses one line into a record owned by the caller together with
// its body.
func parseOne(t parseT, line string) ipfw.ParsedRecord {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser(line+"\n", ipfw.WithLabels()).Next(&state)
	require.Nil(t, err)
	require.NotEqual(t, ipfw.RecordEOF, rec.Kind)
	return ipfw.NewParsedRecord(rec, &state)
}

// collectRuleset parses a whole ruleset into records owned by the caller.
func collectRuleset(t parseT, src string) []ipfw.ParsedRecord {
	parser := ipfw.NewParser(src, ipfw.WithLabels())
	var state ipfw.ReduceState
	var records []ipfw.ParsedRecord
	for {
		state.Reset()
		rec, err := parser.Next(&state)
		require.Nil(t, err)
		if rec.Kind == ipfw.RecordEOF {
			return records
		}
		records = append(records, ipfw.NewParsedRecord(rec, &state))
	}
}

// requireCanonical formats the record of one parsed line, checks the exact
// canonical text, and parses the canonical text back into the same record
// and body.
func requireCanonical(t parseT, input, canonical string) {
	parsed := parseOne(t, input)
	text, err := ipfw.NewFormatter().Record(parsed)
	require.NoError(t, err)
	require.Equal(t, canonical, text)

	reparsed := parseOne(t, canonical)
	expected := parsed.Record
	expected.Text = canonical
	require.Equal(t, expected, reparsed.Record)
	require.Equal(t, emptyToNil(parsed.Body), emptyToNil(reparsed.Body))
	require.Equal(t, parsed.BodyKind, reparsed.BodyKind)
}

// fullBodyState is the collected state of a body with a token in every
// slice.
func fullBodyState() ipfw.ReduceState {
	return ipfw.ReduceState{
		IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPv4}},
		Protos: []ipfw.ProtoMatch{
			{Proto: ipfw.Proto{Name: "tcp"}},
			{Proto: ipfw.Proto{Name: "udp"}},
		},
		Sources: []ipfw.Target{
			{Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"},
			{Kind: ipfw.TargetNetwork4, Text: "198.51.100.1"},
		},
		Destinations: []ipfw.Target{
			{Kind: ipfw.TargetNetwork4, Text: "203.0.113.0/24"},
			{Kind: ipfw.TargetNetwork4, Text: "203.0.113.1"},
		},
		SourcePorts: []ipfw.PortMatch{
			{Lo: ipfw.Port{Number: 1024}, Hi: ipfw.Port{Number: 65535}},
		},
		DestinationPorts: []ipfw.PortMatch{{Lo: ipfw.Port{Name: "domain"}, Hi: ipfw.Port{Name: "domain"}}},
		Options:          []ipfw.Opt{{Kind: ipfw.OptIn}},
	}
}

// verifies that a parsed record owns its record and every body slice, so
// reusing the parser and the state leaves it alone.
func Test_ParsedRecord_OwnsRecordAndBody(t *testing.T) {
	src := "add pass { ip4 or tcp or udp } from 192.0.2.0/24,198.51.100.1 1024-65535" +
		" to 203.0.113.0/24,203.0.113.1 domain in"
	parser := ipfw.NewParser(src + "\n")
	var state ipfw.ReduceState
	rec, err := parser.Next(&state)
	require.Nil(t, err)
	parsed := ipfw.NewParsedRecord(rec, &state)

	parser.Reset("add deny ip from any to any\n")
	state.Reset()
	rec, err = parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.RecordInstruction, rec.Kind)
	require.NotEqual(t, src, rec.Text)
	require.Equal(t, src, parsed.Record.Text)
	require.Equal(t, fullBodyState(), parsed.Body)
}

// verifies that a clone of a parsed record owns every body slice.
func Test_ParsedRecord_Clone(t *testing.T) {
	parsed := ipfw.ParsedRecord{Body: fullBodyState()}
	clone := parsed.Clone()

	parsed.Body.IPProtos[0].Neg = true
	parsed.Body.Protos[0].Proto = ipfw.Proto{Name: "sctp"}
	parsed.Body.Sources[0] = ipfw.Target{Kind: ipfw.TargetAny}
	parsed.Body.Destinations[0] = ipfw.Target{Kind: ipfw.TargetMe}
	parsed.Body.SourcePorts[0].Neg = true
	parsed.Body.DestinationPorts[0].Neg = true
	parsed.Body.Options[0] = ipfw.Opt{Kind: ipfw.OptOut}

	require.Equal(t, fullBodyState(), clone.Body)
	require.Equal(t, ipfw.ReduceState{}, ipfw.ParsedRecord{}.Clone().Body)
}

// verifies that retained instructions remember which body grammar produced them.
func Test_ParsedRecord_BodyKind(t *testing.T) {
	cases := []struct {
		line string
		kind ipfw.RuleBodyKind
	}{
		{line: "add pass ip from any to any", kind: ipfw.RuleBodyLegacy},
		{line: "add pass in", kind: ipfw.RuleBodyNative},
		{line: "add pass // memo", kind: ipfw.RuleBodyNative},
		{line: "add // memo", kind: ipfw.RuleBodyCommentOnly},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			record := parseOne(t, tc.line)
			require.Equal(t, tc.kind, record.BodyKind)
		})
	}
}

// verifies that a cloned state owns every slice and that IsEmpty tells a
// state without tokens from one with them.
func Test_ReduceState_Clone(t *testing.T) {
	state := fullBodyState()
	clone := state.Clone()

	state.Protos[0].Neg = true
	state.Options = append(state.Options, ipfw.Opt{Kind: ipfw.OptOut})
	require.Equal(t, fullBodyState(), clone)

	require.True(t, ipfw.ReduceState{}.IsEmpty())
	require.False(t, state.IsEmpty())
	require.False(t, clone.IsEmpty())
	state.Reset()
	require.True(t, state.IsEmpty())
}

// verifies the canonical text of the plain record kinds: no bytes for an
// empty record, the hash and the comment text for a comment, the colon and
// the name for a label.
func Test_Formatter_AppendRecord_PlainKinds(t *testing.T) {
	formatter := ipfw.NewFormatter()
	cases := []struct {
		name   string
		record ipfw.ParsedRecord
		text   string
	}{
		{
			name:   "empty record emits nothing",
			record: ipfw.ParsedRecord{Record: ipfw.Record{Kind: ipfw.RecordEmpty}},
			text:   "",
		},
		{
			name:   "comment keeps its text after the hash",
			record: ipfw.ParsedRecord{Record: ipfw.Record{Kind: ipfw.RecordComment, Comment: " blocking rules below"}},
			text:   "# blocking rules below",
		},
		{
			name:   "comment without text",
			record: ipfw.ParsedRecord{Record: ipfw.Record{Kind: ipfw.RecordComment}},
			text:   "#",
		},
		{
			name:   "label",
			record: ipfw.ParsedRecord{Record: ipfw.Record{Kind: ipfw.RecordLabel, Label: "trusted"}},
			text:   ":trusted",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst, err := formatter.AppendRecord(nil, tc.record)
			require.NoError(t, err)
			require.Equal(t, tc.text, string(dst))

			text, err := formatter.Record(tc.record)
			require.NoError(t, err)
			require.Equal(t, tc.text, text)
		})
	}
}

// verifies that an end-of-input or out-of-range record kind is rejected
// without touching the destination.
func Test_Formatter_AppendRecord_UnknownKind(t *testing.T) {
	cases := []struct {
		name   string
		record ipfw.ParsedRecord
		err    error
	}{
		{
			name:   "end of input",
			record: ipfw.ParsedRecord{Record: ipfw.Record{Kind: ipfw.RecordEOF}},
			err:    ipfw.ErrUnknownRecordKind,
		},
		{
			name:   "out of range",
			record: ipfw.ParsedRecord{Record: ipfw.Record{Kind: ipfw.RecordKind(200)}},
			err:    ipfw.ErrUnknownRecordKind,
		},
		{
			name: "empty record with a label",
			record: ipfw.ParsedRecord{Record: ipfw.Record{
				Kind:  ipfw.RecordEmpty,
				Label: "trusted",
			}},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "comment with an instruction",
			record: ipfw.ParsedRecord{Record: ipfw.Record{
				Kind:        ipfw.RecordComment,
				Comment:     " c",
				Instruction: ipfw.Instruction{Tag: 5},
			}},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "label with a table",
			record: ipfw.ParsedRecord{Record: ipfw.Record{
				Kind:  ipfw.RecordLabel,
				Label: "trusted",
				Table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate},
			}},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "comment with a body",
			record: ipfw.ParsedRecord{
				Record: ipfw.Record{Kind: ipfw.RecordComment, Comment: " c"},
				Body:   ipfw.ReduceState{Protos: []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}}},
			},
			err: ipfw.ErrUnexpectedBody,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			formatter := ipfw.NewFormatter()
			dst := []byte("ipfw: ")
			out, err := formatter.AppendRecord(dst, tc.record)
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, "ipfw: ", string(out))

			text, err := formatter.Record(tc.record)
			require.ErrorIs(t, err, tc.err)
			require.Empty(t, text)
		})
	}
}

// verifies that a comment or label a line cannot hold is rejected.
func Test_Formatter_AppendRecord_InvalidText(t *testing.T) {
	cases := []struct {
		name   string
		record ipfw.ParsedRecord
	}{
		{
			name: "comment with a newline",
			record: ipfw.ParsedRecord{Record: ipfw.Record{
				Kind:    ipfw.RecordComment,
				Comment: " two\nlines",
			}},
		},
		{
			name: "comment with trailing whitespace",
			record: ipfw.ParsedRecord{Record: ipfw.Record{
				Kind:    ipfw.RecordComment,
				Comment: " c ",
			}},
		},
		{
			name: "empty label",
			record: ipfw.ParsedRecord{Record: ipfw.Record{
				Kind:  ipfw.RecordLabel,
				Label: "",
			}},
		},
		{
			name: "label with whitespace",
			record: ipfw.ParsedRecord{Record: ipfw.Record{
				Kind:  ipfw.RecordLabel,
				Label: "two words",
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ipfw.NewFormatter().AppendRecord(nil, tc.record)
			require.ErrorIs(t, err, ipfw.ErrInvalidName)
		})
	}
}

// verifies that a ruleset appends one newline per record, an empty record
// contributing only its newline.
func Test_Formatter_AppendRuleset_NewlinePerRecord(t *testing.T) {
	records := []ipfw.ParsedRecord{
		parseOne(t, ":trusted"),
		parseOne(t, ""),
		parseOne(t, "# blocking rules below"),
	}
	dst, err := ipfw.NewFormatter().AppendRuleset([]byte("fw.conf:\n"), records)
	require.NoError(t, err)
	require.Equal(t, "fw.conf:\n:trusted\n\n# blocking rules below\n", string(dst))
}

// verifies that a record a ruleset cannot hold fails the whole ruleset and
// leaves the destination at its original length.
func Test_Formatter_AppendRuleset_ErrorLeavesDestination(t *testing.T) {
	records := []ipfw.ParsedRecord{
		parseOne(t, "# first"),
		{Record: ipfw.Record{Kind: ipfw.RecordEOF}},
		parseOne(t, ":trusted"),
	}
	dst := []byte("prefix")
	out, err := ipfw.NewFormatter().AppendRuleset(dst, records)
	require.ErrorIs(t, err, ipfw.ErrUnknownRecordKind)
	require.Equal(t, "prefix", string(out))
	require.Equal(t, len("prefix"), cap(out))
}

// verifies the canonical action keywords, the alias ones folded, with the
// rule number, the log part, the tag, every skipto form and check-state.
func Test_Formatter_AppendRecord_Actions(t *testing.T) {
	cases := [][2]string{
		{"add allow ip from any to any", "add pass ip from any to any"},
		{"add accept ip from any to any", "add pass ip from any to any"},
		{"add permit ip from any to any", "add pass ip from any to any"},
		{"add drop ip from any to any", "add deny ip from any to any"},
		{"add count ip from any to any", "add count ip from any to any"},
		{"add 100 pass ip from any to any", "add 100 pass ip from any to any"},
		{"add 0007 pass ip from any to any", "add 7 pass ip from any to any"},
		{"add pass log ip from any to any", "add pass log ip from any to any"},
		{"add pass log logamount 500 ip from any to any", "add pass log logamount 500 ip from any to any"},
		{"add pass tag 5 ip from any to any", "add pass tag 5 ip from any to any"},
		{
			"add 100 deny log logamount 5 tag 7 tcp from any to any",
			"add 100 deny log logamount 5 tag 7 tcp from any to any",
		},
		{"add skipto :trusted ip from any to any", "add skipto :trusted ip from any to any"},
		{"add skipto 100 ip from any to any", "add skipto 100 ip from any to any"},
		{"add skipto tablearg ip from any to any", "add skipto tablearg ip from any to any"},
		{"add check-state", "add check-state"},
		{"add check-state :flow", "add check-state :flow"},
		{"add check-state :flow // cached", "add check-state :flow // cached"},
		{"add check-state log", "add check-state log"},
		{"add 42 check-state :flow log logamount 10 tag 3", "add 42 check-state :flow log logamount 10 tag 3"},
	}
	for _, tc := range cases {
		t.Run(tc[0], func(t *testing.T) {
			requireCanonical(t, tc[0], tc[1])
		})
	}
}

// verifies the canonical protocol section: one keyword folded per version
// set, a lone match without braces, several matches in a braced group with
// the IP versions first.
func Test_Formatter_AppendRecord_Protocols(t *testing.T) {
	cases := [][2]string{
		{"add pass ip from any to any", "add pass ip from any to any"},
		{"add pass all from any to any", "add pass ip from any to any"},
		{"add pass ip4 from any to any", "add pass ip4 from any to any"},
		{"add pass ipv4 from any to any", "add pass ip4 from any to any"},
		{"add pass ipv6 from any to any", "add pass ip6 from any to any"},
		{"add pass not ip4 from any to any", "add pass not ip4 from any to any"},
		{"add pass not tcp from any to any", "add pass not tcp from any to any"},
		{"add pass { 6 } from any to any", "add pass 6 from any to any"},
		{"add pass not 6 from any to any", "add pass not 6 from any to any"},
		{"add pass 0 from any to any", "add pass 0 from any to any"},
		{"add pass { 300 } from any to any", "add pass 300 from any to any"},
		{"add pass not not from any to any", "add pass not not from any to any"},
		{"add pass { tcp or udp } from any to any", "add pass { tcp or udp } from any to any"},
		{"add pass { log } from any to any", "add pass { log } from any to any"},
		{"add pass { tag } from any to any", "add pass { tag } from any to any"},
		{"add pass { logx } from any to any", "add pass { logx } from any to any"},
		{"add pass { tagx } from any to any", "add pass { tagx } from any to any"},
		{"add pass not log from any to any", "add pass not log from any to any"},
		{
			"add pass { ip4 or not tcp or udp } from any to any",
			"add pass { ip4 or not tcp or udp } from any to any",
		},
		{"add pass { udp or ip4 } from any to any", "add pass { ip4 or udp } from any to any"},
	}
	for _, tc := range cases {
		t.Run(tc[0], func(t *testing.T) {
			requireCanonical(t, tc[0], tc[1])
		})
	}
}

// verifies the canonical target section: one comma chain without braces and
// under one negation, several chains in a braced group, quoted hostnames
// unquoted and single members without braces.
func Test_Formatter_AppendRecord_Targets(t *testing.T) {
	cases := [][2]string{
		{
			"add pass ip from not 192.0.2.1,198.51.100.1 to any",
			"add pass ip from not 192.0.2.1,198.51.100.1 to any",
		},
		{
			"add pass ip from not 192.0.2.1, 198.51.100.1 to any",
			"add pass ip from not 192.0.2.1,198.51.100.1 to any",
		},
		{
			"add pass ip from { not 192.0.2.1 or not 198.51.100.1 } to any",
			"add pass ip from { not 192.0.2.1 or not 198.51.100.1 } to any",
		},
		{
			"add pass ip from not host.example.com,192.0.2.1 to any",
			"add pass ip from not host.example.com,192.0.2.1 to any",
		},
		{"add pass ip from { 192.0.2.0/24 or ::1 } to any", "add pass ip from { 192.0.2.0/24 or ::1 } to any"},
		{
			"add pass ip from { 2001:db8::1, 2001:db8::2 or 192.0.2.0/24 } to any",
			"add pass ip from { 2001:db8::1,2001:db8::2 or 192.0.2.0/24 } to any",
		},
		{"add pass ip from `node-1.example.net' to any", "add pass ip from node-1.example.net to any"},
		{
			"add allow tcp from { host.example.com } to `node-1.example.net'",
			"add pass tcp from host.example.com to node-1.example.net",
		},
		{
			"add allow tcp from { table(_SRV_) } to table(_DST_)",
			"add pass tcp from table(_SRV_) to table(_DST_)",
		},
		{"add pass ip from me to me6", "add pass ip from me to me6"},
		{"add pass ip from not me to any", "add pass ip from not me to any"},
		{"add pass ip from _MACRO_ to any", "add pass ip from _MACRO_ to any"},
	}
	for _, tc := range cases {
		t.Run(tc[0], func(t *testing.T) {
			requireCanonical(t, tc[0], tc[1])
		})
	}
}

// verifies that a wrapped pattern index still keeps the target alternatives braced.
func Test_Formatter_AppendRecord_TargetPatternWrap(t *testing.T) {
	record := instructionRecord()
	record.Body.Sources = make([]ipfw.Target, 1<<16+1)
	for idx := range record.Body.Sources {
		record.Body.Sources[idx] = ipfw.Target{
			Pattern: uint16(idx),
			Kind:    ipfw.TargetAny,
		}
	}
	text, err := ipfw.NewFormatter().Record(record)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(text, "add pass ip from { "))
	require.True(t, strings.HasSuffix(text, " } to any"))
}

// verifies the canonical port sections: lists comma-joined without spaces
// under one negation, ranges, names with escapes and leading zeros folded.
func Test_Formatter_AppendRecord_Ports(t *testing.T) {
	cases := [][2]string{
		{"add pass tcp from any 22 to any", "add pass tcp from any 22 to any"},
		{"add pass tcp from any 1024-65535 to any", "add pass tcp from any 1024-65535 to any"},
		{"add pass tcp from any 22,80,443 to any", "add pass tcp from any 22,80,443 to any"},
		{"add pass tcp from any 22,80 to any", "add pass tcp from any 22,80 to any"},
		{"add pass tcp from any ftp\\-data to any", "add pass tcp from any ftp\\-data to any"},
		{"add pass tcp from any not 22,80 to any", "add pass tcp from any not 22,80 to any"},
		{"add pass tcp from any not 22-23,80 to any", "add pass tcp from any not 22-23,80 to any"},
		{"add pass tcp from any not 22 to any", "add pass tcp from any not 22 to any"},
		{"add pass tcp from any to any domain", "add pass tcp from any to any domain"},
		{"add pass tcp from any 22 to any 80", "add pass tcp from any 22 to any 80"},
		{"add pass tcp from any 22-ssh to any", "add pass tcp from any 22-ssh to any"},
		{"add pass tcp from any 007 to any", "add pass tcp from any 7 to any"},
		{"add pass tcp from any to any not", "add pass tcp from any to any not-not"},
		{"add pass tcp from any to any to", "add pass tcp from any to any to-to"},
		{"add pass tcp from any to any to in", "add pass tcp from any to any to-to in"},
		{"add pass tcp from any not-not to any", "add pass tcp from any not-not to any"},
		{"add pass tcp from any to-to to any", "add pass tcp from any to-to to any"},
		{"add pass tcp from any 22,to to any", "add pass tcp from any 22,to to any"},
		{"add pass tcp from any to any 22,in", "add pass tcp from any to any 22,in"},
		{`add pass tcp from any a\ to any`, `add pass tcp from any a\ to any`},
		{`add pass tcp from any proto\ to any`, `add pass tcp from any proto\ to any`},
		{`add pass tcp from any to any a\`, `add pass tcp from any to any a\`},
		{"add pass tcp from any to any dst-port not", "add pass tcp from any to any dst-port not"},
		{"add pass tcp from any proto to any", "add pass tcp from any proto to any"},
	}
	for _, tc := range cases {
		t.Run(tc[0], func(t *testing.T) {
			requireCanonical(t, tc[0], tc[1])
		})
	}
}

// verifies the canonical option list: options in stored order, Or groups
// braced, port lists comma-joined, type sets and TCP flags in canonical order.
func Test_Formatter_AppendRecord_Options(t *testing.T) {
	cases := [][2]string{
		{"add pass ip from any to any in", "add pass ip from any to any in"},
		{"add pass ip from any to any in out", "add pass ip from any to any in out"},
		{"add pass ip from any to any not diverted", "add pass ip from any to any not diverted"},
		{"add pass ip from any to any { in or out }", "add pass ip from any to any { in or out }"},
		{"add pass ip from any to any frag", "add pass ip from any to any frag"},
		{"add pass ip from any to any antispoof", "add pass ip from any to any antispoof"},
		{"add pass tcp from any to any established keep-state", "add pass tcp from any to any established keep-state"},
		{"add pass ip from any to any keep-state :flow", "add pass ip from any to any keep-state :flow"},
		{"add pass ip from any to any proto tcp", "add pass ip from any to any proto tcp"},
		{"add pass ip from any to any proto ipv6", "add pass ip from any to any proto ipv6"},
		{"add pass ip from any to any proto 6", "add pass ip from any to any proto 6"},
		{
			"add pass icmp from any to any icmptypes 8,3,11",
			"add pass icmp from any to any icmptypes 3,8,11",
		},
		{
			"add pass ip from any to any icmp6types 135,128",
			"add pass ip from any to any icmp6types 128,135",
		},
		{
			"add pass tcp from any to any tcpflags !ack,syn",
			"add pass tcp from any to any tcpflags syn,!ack",
		},
		{
			"add pass tcp from any to any tcpflags syn,!ack",
			"add pass tcp from any to any tcpflags syn,!ack",
		},
		{
			"add pass tcp from any to any tcpflags syn,!syn",
			"add pass tcp from any to any tcpflags syn,!syn",
		},
		{
			"add pass tcp from any to any tcpflags urg,ack,psh,rst,syn,fin",
			"add pass tcp from any to any tcpflags fin,syn,rst,psh,ack,urg",
		},
		{"add pass ip from any to any via eth0", "add pass ip from any to any via eth0"},
		{"add pass ip from any to any via vlan1??", "add pass ip from any to any via vlan1??"},
		{"add pass ip from any to any via table(t)", "add pass ip from any to any via table(t)"},
		{"add pass ip from any to any via table(t,:L)", "add pass ip from any to any via table(t,:L)"},
		{"add pass ip from any to any { via lo0 or via lo1 }", "add pass ip from any to any { via lo0 or via lo1 }"},
		{
			"add pass tcp from any to any dst-port 8080,8443",
			"add pass tcp from any to any dst-port 8080,8443",
		},
		{
			"add pass tcp from any to any not dst-port 22,80",
			"add pass tcp from any to any not dst-port 22,80",
		},
		{
			"add pass tcp from any to any { not dst-port 22,80 or in }",
			"add pass tcp from any to any { not dst-port 22,80 or in }",
		},
		{
			"add pass tcp from any to any { not dst-port 22,80 }",
			"add pass tcp from any to any { not dst-port 22,80 }",
		},
		{
			"add pass tcp from any to any { in or dst-port 22,80 }",
			"add pass tcp from any to any { in or dst-port 22,80 }",
		},
		{
			"add pass tcp from any to any src-port 1024-65535",
			"add pass tcp from any to any src-port 1024-65535",
		},
		{
			`add pass tcp from any to any dst-port proto\`,
			`add pass tcp from any to any dst-port proto\`,
		},
		{
			"add pass ip from any to any in via eth0 established",
			"add pass ip from any to any in via eth0 established",
		},
		{
			"add allow tcp from any to any 22 established",
			"add pass tcp from any to any 22 established",
		},
		{
			"add pass ip from any to any { in or out } via eth0",
			"add pass ip from any to any { in or out } via eth0",
		},
		{
			"add pass ip from any to any in { out or frag }",
			"add pass ip from any to any in { out or frag }",
		},
		{
			"add pass ip from any to any { in or out } { frag or diverted }",
			"add pass ip from any to any { in or out } { frag or diverted }",
		},
	}
	for _, tc := range cases {
		t.Run(tc[0], func(t *testing.T) {
			requireCanonical(t, tc[0], tc[1])
		})
	}
}

// verifies the whole instruction line: header, body and inline comment in
// grammar order on one line.
func Test_Formatter_AppendRecord_Instruction(t *testing.T) {
	cases := [][2]string{
		{
			"add 100 deny log logamount 5 tag 7 tcp from not 192.0.2.0/24,198.51.100.1" +
				" 1024-65535 to { 203.0.113.0/24 or `node-1.example.net' } 80-90" +
				" { in or via table(_IFACES_) } // bots",
			"add 100 deny log logamount 5 tag 7 tcp from not 192.0.2.0/24,198.51.100.1" +
				" 1024-65535 to { 203.0.113.0/24 or node-1.example.net } 80-90" +
				" { in or via table(_IFACES_) } // bots",
		},
		{
			"add pass ip from any to any // bots",
			"add pass ip from any to any // bots",
		},
		{"add pass ip from any to any //x", "add pass ip from any to any //x"},
		{
			"add pass ip from any to any  // c \t",
			"add pass ip from any to any // c",
		},
		{"add pass ip from any to any //", "add pass ip from any to any"},
		{"add 110 allow in", "add 110 pass in"},
		{"add allow proto tcp", "add pass proto tcp"},
		{"add allow // memo", "add pass // memo"},
		{"add count //x", "add count //x"},
		{
			"add pass ip from any to any#metadata",
			"add pass ip from any to any #metadata",
		},
		{
			"add pass ip from any to any // slash # metadata",
			"add pass ip from any to any // slash # metadata",
		},
		{
			"add 100 // note # metadata",
			"add 100 // note # metadata",
		},
		{"add //", "add //"},
	}
	for _, tc := range cases {
		t.Run(tc[1], func(t *testing.T) {
			requireCanonical(t, tc[0], tc[1])
		})
	}
}

// verifies the canonical table commands: create with and without a type,
// add with a key of every shape and an optional value.
func Test_Formatter_AppendRecord_Tables(t *testing.T) {
	cases := [][2]string{
		{"table _JUMP_IN_ create type iface", "table _JUMP_IN_ create type iface"},
		{"table t create", "table t create"},
		{"table t create type addr", "table t create type addr"},
		{"table t create type number", "table t create type number"},
		{"table t create type flow", "table t create type flow"},
		{"table t create type mac", "table t create type mac"},
		{"table t add 192.0.2.0/24 :L", "table t add 192.0.2.0/24 :L"},
		{"table t add 2001:db8::1", "table t add 2001:db8::1"},
		{"table t add host.example.com", "table t add host.example.com"},
		{"table t add vlan7", "table t add vlan7"},
		{"table t add vlan7 :JUMP", "table t add vlan7 :JUMP"},
		{"table t create#metadata", "table t create #metadata"},
	}
	for _, tc := range cases {
		t.Run(tc[0], func(t *testing.T) {
			requireCanonical(t, tc[0], tc[1])
		})
	}
}

// verifies that a whole ruleset keeps its record order, labels around a
// symbolic skipto, empty lines and comments, already-canonical text coming
// back identical.
func Test_Formatter_AppendRuleset_AllKinds(t *testing.T) {
	src := "# fw: experimental\n" +
		"table _BLOCK_ create type addr\n" +
		"\n" +
		"add 100 skipto :trusted ip from table(_BLOCK_) to any\n" +
		":trusted\n" +
		"\n" +
		"add 200 pass log tcp from any to 192.0.2.0/24 443 // https\n"
	dst, err := ipfw.NewFormatter().AppendRuleset(nil, collectRuleset(t, src))
	require.NoError(t, err)
	require.Equal(t, src, string(dst))
}

// verifies that labels retain trailing hash metadata when label parsing is enabled.
func Test_Formatter_AppendRecord_LabelHashComment(t *testing.T) {
	requireCanonical(t, ":trusted# metadata", ":trusted # metadata")
}

// verifies that source whitespace, line spacing and comments are folded to
// the canonical form, the final newline owned by the ruleset level.
func Test_Formatter_AppendRuleset_Normalizes(t *testing.T) {
	records := collectRuleset(t, "  add   pass\tip  from  any to any  \n\n\t:trusted \t\n#  c\n")
	dst, err := ipfw.NewFormatter().AppendRuleset(nil, records)
	require.NoError(t, err)
	require.Equal(t, "add pass ip from any to any\n\n:trusted\n#  c\n", string(dst))

	records = collectRuleset(t, ":L")
	dst, err = ipfw.NewFormatter().AppendRuleset(nil, records)
	require.NoError(t, err)
	require.Equal(t, ":L\n", string(dst), "a final record without a newline still gets one")
}

// requireSectionReparses cuts the section between after and the first
// occurrence of until out of line and requires the sub-parser to consume it
// wholly into the expected state.
func requireSectionReparses(
	t *testing.T,
	line, after, until string,
	parse func(string, ipfw.State) (int, error),
	expected ipfw.ReduceState,
) {
	t.Helper()
	rest, ok := strings.CutPrefix(line, after)
	require.True(t, ok, "the line must start with %q", after)
	fragment := rest
	if until != "" {
		var found bool
		fragment, _, found = strings.Cut(rest, until)
		require.True(t, found, "the line must contain %q after %q", until, after)
	}
	var state ipfw.ReduceState
	n, err := parse(fragment, &state)
	require.NoError(t, err)
	require.Equal(t, len(fragment), n, "the fragment must be consumed wholly")
	require.Equal(t, expected, emptyToNil(state))
}

// verifies that the canonical sections read back through the exported
// sub-parsers as the whole state and its exact length.
func Test_Formatter_Sections_Reparses(t *testing.T) {
	requireSectionReparses(
		t,
		"add pass { ip4 or not tcp } from not 192.0.2.1,198.51.100.1 to any",
		"add pass ", " from",
		ipfw.ParseProtocols,
		ipfw.ReduceState{
			IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPv4}},
			Protos:   []ipfw.ProtoMatch{{Neg: true, Proto: ipfw.Proto{Name: "tcp"}}},
		},
	)
	requireSectionReparses(
		t,
		"add pass ip from not 192.0.2.1,198.51.100.1 to any",
		"add pass ip from ", " to",
		ipfw.ParseSourceTargets,
		ipfw.ReduceState{
			Sources: []ipfw.Target{
				{Neg: true, Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"},
				{Neg: true, Kind: ipfw.TargetNetwork4, Text: "198.51.100.1"},
			},
		},
	)
	requireSectionReparses(
		t,
		"add pass tcp from any not 22,80 to any",
		"add pass tcp from any ", " to",
		ipfw.ParseSourcePorts,
		ipfw.ReduceState{
			SourcePorts: []ipfw.PortMatch{
				{Neg: true, Lo: ipfw.Port{Number: 22}, Hi: ipfw.Port{Number: 22}},
				{Neg: true, Lo: ipfw.Port{Number: 80}, Hi: ipfw.Port{Number: 80}},
			},
		},
	)
	requireSectionReparses(
		t,
		"add pass tcp from any to any { dst-port 22 or dst-port 80 } in",
		"add pass tcp from any to any ", "",
		func(s string, state ipfw.State) (int, error) {
			return ipfw.ParseOptions(s, state, nil)
		},
		ipfw.ReduceState{
			Options: []ipfw.Opt{
				{Kind: ipfw.OptDestinationPort, Ports: portRangeNumber(22)},
				{Or: true, Kind: ipfw.OptDestinationPort, Ports: portRangeNumber(80)},
				{Kind: ipfw.OptIn},
			},
		},
	)
}

// portRangeNumber is one numeric port range for an option.
func portRangeNumber(number uint16) ipfw.PortRange {
	port := ipfw.Port{Number: number}
	return ipfw.PortRange{Lo: port, Hi: port}
}

// instructionRecord is a hand-built minimal instruction record, one field
// of it broken per test case.
func instructionRecord() ipfw.ParsedRecord {
	return ipfw.ParsedRecord{
		Record: ipfw.Record{
			Kind:        ipfw.RecordInstruction,
			Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
		},
		Body: ipfw.ReduceState{
			IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
			Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
			Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
		},
	}
}

// verifies that a hand-built value the parser cannot produce is rejected
// with the error of the broken field, one field per case.
func Test_Formatter_AppendRecord_InvalidValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ipfw.ParsedRecord)
		err    error
	}{
		{
			name: "unknown action kind",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.Kind = ipfw.ActionKind(99)
			},
			err: ipfw.ErrUnknownActionKind,
		},
		{
			name: "unknown skipto kind",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.Kind = ipfw.ActionSkipTo
				record.Record.Instruction.Action.SkipTo.Kind = ipfw.SkipToKind(99)
			},
			err: ipfw.ErrUnknownSkipToKind,
		},
		{
			name: "zero numeric skipto",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.Kind = ipfw.ActionSkipTo
				record.Record.Instruction.Action.SkipTo = ipfw.SkipTo{Kind: ipfw.SkipToNumber}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "skipto label with whitespace",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.Kind = ipfw.ActionSkipTo
				record.Record.Instruction.Action.SkipTo = ipfw.SkipTo{Kind: ipfw.SkipToLabel, Label: "two words"}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "flow on another action",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.Flow = "flow"
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "check-state flow with whitespace",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action = ipfw.Action{Kind: ipfw.ActionCheckState, Flow: "two words"}
				record.Body = ipfw.ReduceState{}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "skipto fields on another action",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.SkipTo = ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 5}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "logamount without log",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Log = ipfw.Log{HasAmount: true, Amount: 5}
			},
			err: ipfw.ErrInvalidLog,
		},
		{
			name: "amount without logamount",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Log = ipfw.Log{Enabled: true, Amount: 5}
			},
			err: ipfw.ErrInvalidLog,
		},
		{
			name: "missing protocol",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.IPProtos = nil
			},
			err: ipfw.ErrMissingProtocol,
		},
		{
			name: "missing source",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = nil
			},
			err: ipfw.ErrMissingSource,
		},
		{
			name: "missing destination",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Destinations = nil
			},
			err: ipfw.ErrMissingDestination,
		},
		{
			name: "check-state with a body",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.Kind = ipfw.ActionCheckState
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "inline comment with a newline",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.InlineComment = "two\nlines"
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "inline comment with a hash",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.InlineComment = "before#after"
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "IP version set without a keyword",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.IPProtos = []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIP(7)}}
			},
			err: ipfw.ErrUnknownProtoKind,
		},
		{
			name: "protocol named by an IP keyword",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.IPProtos = nil
				record.Body.Protos = []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "ip"}}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "protocol named by a plain number",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.IPProtos = nil
				record.Body.Protos = []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "6"}}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "zero numeric protocol",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.IPProtos = nil
				record.Body.Protos = []ipfw.ProtoMatch{{Proto: ipfw.Proto{}}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "protocol named not without negation",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.IPProtos = nil
				record.Body.Protos = []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "not"}}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "protocol name with a stray number",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.IPProtos = nil
				record.Body.Protos = []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp", Number: 6}}}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "unknown target kind",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetKind(99)}}
			},
			err: ipfw.ErrUnknownTargetKind,
		},
		{
			name: "or-continuation without a predecessor",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Pattern: 1, Kind: ipfw.TargetAny}}
			},
			err: ipfw.ErrBrokenOrChain,
		},
		{
			name: "address-list continuation of any",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{
					{Kind: ipfw.TargetAny},
					{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"},
				}
			},
			err: ipfw.ErrBrokenOrChain,
		},
		{
			name: "address-list continuation not listable",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{
					{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"},
					{Kind: ipfw.TargetMe},
				}
			},
			err: ipfw.ErrBrokenOrChain,
		},
		{
			name: "address-list negation mismatch",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{
					{Neg: true, Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"},
					{Kind: ipfw.TargetNetwork4, Text: "198.51.100.1"},
				}
			},
			err: ipfw.ErrInconsistentNegation,
		},
		{
			name: "non-consecutive target pattern",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{
					{Kind: ipfw.TargetAny},
					{Pattern: 2, Kind: ipfw.TargetMe},
				}
			},
			err: ipfw.ErrBrokenOrChain,
		},
		{
			name: "mixed-family address list",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{
					{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"},
					{Kind: ipfw.TargetNetwork6, Text: "2001:db8::1"},
				}
			},
			err: ipfw.ErrBrokenOrChain,
		},
		{
			name: "any with text",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetAny, Text: "x"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "hostname of network shape",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "192.0.2.1"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "custom with whitespace",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "a b"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "custom of table shape",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "table(t)"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "custom with text after a table target",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "table(a)b"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "custom starting with a brace",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "{a"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "custom named not ending a pattern",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "not"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "table name with the closing paren",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetTable, Text: "a)b"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "empty table target name",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Sources = []ipfw.Target{{Kind: ipfw.TargetTable}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "port list negation mismatch",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.SourcePorts = []ipfw.PortMatch{
					{Lo: ipfw.Port{Number: 22}, Hi: ipfw.Port{Number: 22}},
					{Neg: true, Lo: ipfw.Port{Number: 80}, Hi: ipfw.Port{Number: 80}},
				}
			},
			err: ipfw.ErrInconsistentNegation,
		},
		{
			name: "port named by a plain number",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.SourcePorts = []ipfw.PortMatch{{Lo: ipfw.Port{Name: "22"}, Hi: ipfw.Port{Name: "22"}}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "port name with a stray number",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.SourcePorts = []ipfw.PortMatch{
					{Lo: ipfw.Port{Name: "ssh", Number: 22}, Hi: ipfw.Port{Name: "ssh", Number: 22}},
				}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "port name with a bad escape",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.SourcePorts = []ipfw.PortMatch{
					{Lo: ipfw.Port{Name: `a\x`}, Hi: ipfw.Port{Name: `a\x`}},
				}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "port range opening with a trailing escape",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.SourcePorts = []ipfw.PortMatch{
					{Lo: ipfw.Port{Name: `a\`}, Hi: ipfw.Port{Number: 80}},
				}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "destination port named after an option keyword",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.DestinationPorts = []ipfw.PortMatch{{Lo: ipfw.Port{Name: "in"}, Hi: ipfw.Port{Name: "in"}}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "destination port extending an option keyword",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.DestinationPorts = []ipfw.PortMatch{{Lo: ipfw.Port{Name: "fragile"}, Hi: ipfw.Port{Name: "fragile"}}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "destination port named after established alias",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.DestinationPorts = []ipfw.PortMatch{
					{Lo: ipfw.Port{Name: "estab"}, Hi: ipfw.Port{Name: "estab"}},
				}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "destination port named after tcpflags alias",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.DestinationPorts = []ipfw.PortMatch{
					{Lo: ipfw.Port{Name: "tcpflgs"}, Hi: ipfw.Port{Name: "tcpflgs"}},
				}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "via exact named like a table lookup",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{viaExact("table(t)")}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "interface key of network shape",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{
					Name: "t",
					Kind: ipfw.TableAdd,
					Key:  ipfw.TableKey{Kind: ipfw.TableKeyName, Text: "192.0.2.1"},
				}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "option or-continuation without a predecessor",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{{Or: true, Kind: ipfw.OptIn}}
			},
			err: ipfw.ErrBrokenOrChain,
		},
		{
			name: "port-list continuation without a predecessor",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{
					{PortOr: true, Kind: ipfw.OptDestinationPort, Ports: portRangeNumber(22)},
				}
			},
			err: ipfw.ErrBrokenOrChain,
		},
		{
			name: "keep-state in an option group",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{
					{Kind: ipfw.OptIn},
					{Or: true, Kind: ipfw.OptKeepState},
				}
			},
			err: ipfw.ErrStateOptionInGroup,
		},
		{
			name: "duplicate keep-state",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{
					{Kind: ipfw.OptKeepState},
					{Kind: ipfw.OptKeepState, Text: "flow"},
				}
			},
			err: ipfw.ErrDuplicateStateOption,
		},
		{
			name: "comment option",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptComment, Text: " c"}}
			},
			err: ipfw.ErrUnknownOptionKind,
		},
		{
			name: "skipto tablearg with a number",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.Kind = ipfw.ActionSkipTo
				record.Record.Instruction.Action.SkipTo = ipfw.SkipTo{
					Kind:   ipfw.SkipToTableArg,
					Number: 100,
				}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "skipto number with a label",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Instruction.Action.Kind = ipfw.ActionSkipTo
				record.Record.Instruction.Action.SkipTo = ipfw.SkipTo{
					Kind:   ipfw.SkipToNumber,
					Label:  "trusted",
					Number: 100,
				}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "unknown option kind",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptKind(99)}}
			},
			err: ipfw.ErrUnknownOptionKind,
		},
		{
			name: "keyword option with text",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptIn, Text: "x"}}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "port option with a proto",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{
					{Kind: ipfw.OptSourcePort, Ports: portRangeNumber(22), Proto: ipfw.Proto{Name: "tcp"}},
				}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "empty type set",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptICMPTypes}}
			},
			err: ipfw.ErrEmptyTypeSet,
		},
		{
			name: "unknown icmp type",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{icmpTypes(32)}
			},
			err: ipfw.ErrUnknownICMPType,
		},
		{
			name: "unknown icmp6 type",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{icmp6Types(202)}
			},
			err: ipfw.ErrUnknownICMP6Type,
		},
		{
			name: "keep-state flow with whitespace",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptKeepState, Text: "two words"}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "proto option named by a plain number",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptProto, Proto: ipfw.Proto{Name: "6"}}}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "tcpflags without a mask",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{tcpFlags(0, 0)}
			},
			err: ipfw.ErrInvalidTCPFlags,
		},
		{
			name: "tcpflags with an unknown bit",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{tcpFlags(ipfw.TCPFlag(1<<6), ipfw.TCPFlag(1<<6))}
			},
			err: ipfw.ErrInvalidTCPFlags,
		},
		{
			name: "unknown via kind",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{
					{Kind: ipfw.OptVia, Via: ipfw.Via{Kind: ipfw.ViaKind(99), Name: "eth0"}},
				}
			},
			err: ipfw.ErrUnknownViaKind,
		},
		{
			name: "via exact with a glob",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{viaExact("eth*")}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "via exact with a value",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{
					{Kind: ipfw.OptVia, Via: ipfw.Via{Kind: ipfw.ViaExact, Name: "eth0", Value: "v"}},
				}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "via table name with the closing paren",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{viaTable("a)b", "")}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "custom option without an appender",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "myopt", Arg: "42"}}
			},
			err: ipfw.ErrMissingCustomOptAppender,
		},
		{
			name: "unknown table kind",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{Name: "t", Kind: ipfw.TableKind(99)}
			},
			err: ipfw.ErrUnknownTableKind,
		},
		{
			name: "table name with whitespace",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{Name: "two words", Kind: ipfw.TableCreate}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "unknown table type",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{Name: "t", Kind: ipfw.TableCreate, Type: ipfw.TableType(99)}
			},
			err: ipfw.ErrUnknownTableType,
		},
		{
			name: "create with a key",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{
					Name: "t",
					Kind: ipfw.TableCreate,
					Key:  ipfw.TableKey{Kind: ipfw.TableKeyNetwork4, Text: "192.0.2.1"},
				}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "add with a type",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{
					Name: "t",
					Kind: ipfw.TableAdd,
					Type: ipfw.TableTypeAddr,
					Key:  ipfw.TableKey{Kind: ipfw.TableKeyNetwork4, Text: "192.0.2.1"},
				}
			},
			err: ipfw.ErrUnexpectedBody,
		},
		{
			name: "unknown table key kind",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{
					Name: "t",
					Kind: ipfw.TableAdd,
					Key:  ipfw.TableKey{Kind: ipfw.TableKeyKind(99), Text: "192.0.2.1"},
				}
			},
			err: ipfw.ErrUnknownTableKeyKind,
		},
		{
			name: "IPv4 key of the wrong shape",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{
					Name: "t",
					Kind: ipfw.TableAdd,
					Key:  ipfw.TableKey{Kind: ipfw.TableKeyNetwork4, Text: "vlan7"},
				}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "add value with whitespace",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Body = ipfw.ReduceState{}
				record.Record.Table = ipfw.Table{
					Name:  "t",
					Kind:  ipfw.TableAdd,
					Key:   ipfw.TableKey{Kind: ipfw.TableKeyName, Text: "vlan7"},
					Value: "two words",
				}
			},
			err: ipfw.ErrInvalidName,
		},
		{
			name: "table record with a body",
			mutate: func(record *ipfw.ParsedRecord) {
				record.Record.Kind = ipfw.RecordTable
				record.Record.Instruction = ipfw.Instruction{}
				record.Record.Table = ipfw.Table{Name: "t", Kind: ipfw.TableCreate}
			},
			err: ipfw.ErrUnexpectedBody,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := instructionRecord()
			tc.mutate(&record)
			dst := []byte("ipfw: ")
			out, err := ipfw.NewFormatter().AppendRecord(dst, record)
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, "ipfw: ", string(out))
		})
	}
}

// verifies that a custom option renders through the caller's appender, an
// error of the appender surfacing untouched, and reads back through a
// matching option hook.
func Test_Formatter_CustomOptAppender(t *testing.T) {
	appendCustom := func(dst []byte, opt ipfw.Opt) ([]byte, error) {
		if opt.Arg == "boom" {
			return dst, errors.New("boom")
		}
		dst = append(dst, opt.Text...)
		dst = append(dst, ' ')
		dst = append(dst, opt.Arg...)
		return dst, nil
	}
	record := instructionRecord()
	record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "myopt", Arg: "42"}}
	text, err := ipfw.NewFormatter(ipfw.WithCustomOptAppender(appendCustom)).Record(record)
	require.NoError(t, err)
	require.Equal(t, "add pass ip from any to any myopt 42", text)

	var state ipfw.ReduceState
	hook := func(rest string) (ipfw.Opt, int, error) {
		for _, arg := range []string{"42", "7"} {
			customText := "myopt " + arg
			if strings.HasPrefix(rest, customText) {
				return ipfw.Opt{
					Kind: ipfw.OptCustom,
					Text: "myopt",
					Arg:  arg,
				}, len(customText), nil
			}
		}
		return ipfw.Opt{}, 0, ipfw.ErrUnknownOption
	}
	rec, parseErr := ipfw.NewParser(text+"\n", ipfw.WithOptionHook(hook)).Next(&state)
	require.Nil(t, parseErr)
	require.Equal(t, record.Body, emptyToNil(state))
	require.Equal(t, record.Record.Instruction, rec.Instruction)

	record.Body.Options = []ipfw.Opt{
		{Neg: true, Kind: ipfw.OptCustom, Text: "myopt", Arg: "42"},
		{Or: true, Kind: ipfw.OptCustom, Text: "myopt", Arg: "7"},
	}
	text, err = ipfw.NewFormatter(ipfw.WithCustomOptAppender(appendCustom)).Record(record)
	require.NoError(t, err)
	require.Equal(t, "add pass ip from any to any { not myopt 42 or myopt 7 }", text)
	state.Reset()
	rec, parseErr = ipfw.NewParser(text+"\n", ipfw.WithOptionHook(hook)).Next(&state)
	require.Nil(t, parseErr)
	require.Equal(t, record.Body, emptyToNil(state))
	require.Equal(t, record.Record.Instruction, rec.Instruction)

	record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "myopt", Arg: "boom"}}
	_, err = ipfw.NewFormatter(ipfw.WithCustomOptAppender(appendCustom)).Record(record)
	require.ErrorContains(t, err, "boom")

	record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "myopt", Arg: "#metadata"}}
	_, err = ipfw.NewFormatter(ipfw.WithCustomOptAppender(appendCustom)).Record(record)
	require.ErrorIs(t, err, ipfw.ErrInvalidName)

	record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "inhouse", Arg: "42"}}
	_, err = ipfw.NewFormatter(ipfw.WithCustomOptAppender(appendCustom)).Record(record)
	require.ErrorIs(t, err, ipfw.ErrInvalidName)

	record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "//", Arg: "memo"}}
	_, err = ipfw.NewFormatter(ipfw.WithCustomOptAppender(appendCustom)).Record(record)
	require.ErrorIs(t, err, ipfw.ErrInvalidName)

	emptyCustom := func(dst []byte, _ ipfw.Opt) ([]byte, error) {
		return dst, nil
	}
	_, err = ipfw.NewFormatter(ipfw.WithCustomOptAppender(emptyCustom)).Record(record)
	require.ErrorIs(t, err, ipfw.ErrInvalidName)
}

// verifies that native custom options stay protected from header and legacy grammar prefixes.
func Test_Formatter_CustomOptNativeBody(t *testing.T) {
	customTexts := []string{"tcp from any to any", "logger", "not"}
	hook := func(rest string) (ipfw.Opt, int, error) {
		for _, text := range customTexts {
			if strings.HasPrefix(rest, text) {
				return ipfw.Opt{Kind: ipfw.OptCustom, Text: text}, len(text), nil
			}
		}
		return ipfw.Opt{}, 0, ipfw.ErrUnknownOption
	}
	appender := func(dst []byte, opt ipfw.Opt) ([]byte, error) {
		return append(dst, opt.Text...), nil
	}
	cases := [][2]string{
		{"add pass { tcp from any to any }", "add pass { tcp from any to any }"},
		{"add pass { logger }", "add pass { logger }"},
		{"add pass not// comment", "add pass not// comment"},
		{
			"add pass tcp from any to any not// comment",
			"add pass tcp from any to any not// comment",
		},
		{"add pass not#metadata", "add pass not#metadata"},
		{
			"add pass ip from any to any not#metadata",
			"add pass ip from any to any not#metadata",
		},
	}
	for _, tc := range cases {
		t.Run(tc[0], func(t *testing.T) {
			var state ipfw.ReduceState
			record, parseErr := ipfw.NewParser(tc[0]+"\n", ipfw.WithOptionHook(hook)).Next(&state)
			require.Nil(t, parseErr)
			parsed := ipfw.NewParsedRecord(record, &state)

			text, err := ipfw.NewFormatter(ipfw.WithCustomOptAppender(appender)).Record(parsed)
			require.NoError(t, err)
			require.Equal(t, tc[1], text)

			state.Reset()
			reparsed, parseErr := ipfw.NewParser(text+"\n", ipfw.WithOptionHook(hook)).Next(&state)
			require.Nil(t, parseErr)
			expected := parsed.Record
			expected.Text = text
			require.Equal(t, expected, *reparsed)
			require.Equal(t, parsed.Body, emptyToNil(state))
		})
	}
}

// The pools the line generator picks its invented names from.
var (
	genHostnames   = []string{"host.example.com", "node-1.example.net", "a-b_c.example.org"}
	genCustomNames = []string{"_MACRO_", "inet", "mex", "localnet"}
	genIfNames     = []string{"eth0", "vlan7", "lo0", "tun0"}
	genTableNames  = []string{"_T1_", "_JUMP_", "t"}
	genLabels      = []string{"trusted", "L", "LONG_LABEL_42"}
)

// drawPick draws one of the choices.
func drawPick[T any](t *rapid.T, name string, choices ...T) T {
	return rapid.SampledFrom(choices).Draw(t, name)
}

// drawNot draws an optional negation keyword with its space.
func drawNot(t *rapid.T) string {
	if rapid.Bool().Draw(t, "neg") {
		return "not "
	}
	return ""
}

// genProtocols draws a valid protocol section.
func genProtocols(t *rapid.T) string {
	count := rapid.IntRange(1, 3).Draw(t, "protocols")
	elements := make([]string, 0, count)
	for range count {
		var element string
		if drawPick(t, "ipKind", true, false) {
			element = drawNot(t) + drawPick(t, "ip", "ip", "all", "ip4", "ipv4", "ip6", "ipv6")
		} else {
			element = drawNot(t) + drawPick(t, "proto", "tcp", "udp", "icmp", "esp", "6", "300", "to")
		}
		elements = append(elements, element)
	}
	if len(elements) == 1 {
		return elements[0]
	}
	return "{ " + strings.Join(elements, " or ") + " }"
}

// genAddressMember draws one address-list member.
func genAddressMember(t *rapid.T) string {
	return drawPick(t, "member",
		"192.0.2.1", "198.51.100.0/24", "203.0.113.7",
		"2001:db8::1", "2001:db8:aa::/48",
		drawPick(t, "host", genHostnames...),
		drawPick(t, "custom", genCustomNames...),
	)
}

func genAddressListMember(t *rapid.T, ipv6 bool) string {
	if ipv6 {
		return drawPick(t, "member6",
			"2001:db8::1", "2001:db8:aa::/48",
			drawPick(t, "host6", genHostnames...),
			drawPick(t, "custom6", genCustomNames...),
		)
	}
	return drawPick(t, "member4",
		"192.0.2.1", "198.51.100.0/24", "203.0.113.7",
		drawPick(t, "host4", genHostnames...),
		drawPick(t, "custom4", genCustomNames...),
	)
}

// genTargetChain draws one chain: a lone target of any shape or a comma
// list of address members under one negation.
func genTargetChain(t *rapid.T) string {
	prefix := drawNot(t)
	if drawPick(t, "lone", true, false) {
		return prefix + drawPick(t, "target",
			"any", "me", "me6",
			"table("+drawPick(t, "table", genTableNames...)+")",
			genAddressMember(t),
		)
	}
	ipv6 := rapid.Bool().Draw(t, "listIPv6")
	members := []string{genAddressListMember(t, ipv6)}
	for range rapid.IntRange(1, 2).Draw(t, "members") {
		members = append(members, genAddressListMember(t, ipv6))
	}
	return prefix + strings.Join(members, ",")
}

// genTargets draws one target section, several chains in a braced group.
func genTargets(t *rapid.T) string {
	chains := []string{genTargetChain(t)}
	for range rapid.IntRange(0, 2).Draw(t, "chains") {
		chains = append(chains, genTargetChain(t))
	}
	if len(chains) == 1 {
		return chains[0]
	}
	return "{ " + strings.Join(chains, " or ") + " }"
}

// genPortRange draws one port or inclusive range.
func genPortRange(t *rapid.T) string {
	port := drawPick(t, "port", "22", "80", "1024", "ssh", "domain", `ftp\-data`)
	if drawPick(t, "range", true, false) {
		return port
	}
	return port + "-" + drawPick(t, "hi", "80", "443", "65535", "http", "ssh")
}

// genPorts draws an optional port section.
func genPorts(t *rapid.T) string {
	if !rapid.Bool().Draw(t, "hasPorts") {
		return ""
	}
	ranges := []string{genPortRange(t)}
	for range rapid.IntRange(0, 2).Draw(t, "portRanges") {
		ranges = append(ranges, genPortRange(t))
	}
	return drawNot(t) + strings.Join(ranges, ",")
}

// genOption draws one option with its argument.
func genOption(t *rapid.T) string {
	prefix := drawNot(t)
	switch kind := drawPick(t, "option",
		"in", "out", "established", "frag", "diverted", "antispoof",
		"keep-state", "proto", "tcpflags", "icmptypes", "icmp6types",
		"src-port", "dst-port", "via",
	); kind {
	case "keep-state":
		if drawPick(t, "flow", true, false) {
			return prefix + "keep-state :" + drawPick(t, "flowName", "flow", "f1")
		}
		return prefix + "keep-state"
	case "proto":
		return prefix + "proto " + drawPick(t, "optProto", "tcp", "udp", "6", "ip4", "not", "to")
	case "tcpflags":
		return prefix + "tcpflags " + drawPick(t, "flags", "syn", "syn,!ack", "fin,syn,rst,psh,ack,urg", "!fin,syn")
	case "icmptypes":
		return prefix + "icmptypes " + drawPick(t, "icmp", "0", "3,8", "8,3,11,12")
	case "icmp6types":
		return prefix + "icmp6types " + drawPick(t, "icmp6", "135", "128,133")
	case "src-port", "dst-port":
		return prefix + kind + " " + genPortRange(t)
	case "via":
		switch drawPick(t, "viaKind", "exact", "mask", "table") {
		case "mask":
			return prefix + "via " + drawPick(t, "ifMask", "vlan*", "eth?", "tun[0-9]")
		case "table":
			if drawPick(t, "viaValue", true, false) {
				return prefix + "via table(" + drawPick(t, "viaTable", genTableNames...) + ",:L)"
			}
			return prefix + "via table(" + drawPick(t, "viaTable2", genTableNames...) + ")"
		default:
			return prefix + "via " + drawPick(t, "ifName", genIfNames...)
		}
	default:
		return prefix + kind
	}
}

// genOptions draws an optional option list, its first two options
// occasionally joined into a braced group, a lone one sometimes braced on
// its own.
func genOptions(t *rapid.T) string {
	count := rapid.IntRange(0, 3).Draw(t, "options")
	if count == 0 {
		return ""
	}
	options := make([]string, 0, count)
	stateOptionSeen := false
	for range count {
		option := genOption(t)
		if strings.Contains(option, "keep-state") {
			if stateOptionSeen {
				option = "in"
			} else {
				stateOptionSeen = true
			}
		}
		options = append(options, option)
	}
	joined := strings.Join(options, " ")
	if !stateOptionSeen && count >= 2 && rapid.Bool().Draw(t, "group") {
		joined = "{ " + strings.Join(options[:2], " or ") + " } " + strings.Join(options[2:], " ")
	} else if !stateOptionSeen && count == 1 && rapid.Bool().Draw(t, "singleGroup") {
		joined = "{ " + options[0] + " }"
	}
	return joined
}

// genInstructionLine draws one valid `add` line.
func genInstructionLine(t *rapid.T) string {
	line := "add "
	if num := drawPick(t, "num", "", "100", "0007"); num != "" {
		line += num + " "
	}
	if rapid.IntRange(0, 7).Draw(t, "commentOnly") == 0 {
		return line + drawPick(t, "commentOnlyText", "//", "// c", "//\tmetadata")
	}
	switch action := drawPick(t, "action",
		"pass", "allow", "accept", "deny", "drop", "count", "check-state", "skipto",
	); action {
	case "check-state":
		line += action
		if drawPick(t, "checkFlow", true, false) {
			line += " :flow"
		}
	case "skipto":
		line += action + " " + drawPick(t, "skipto", ":trusted", "100", "tablearg")
	default:
		line += action
	}
	line += drawPick(t, "log", "", " log", " log logamount 500")
	line += drawPick(t, "tag", "", " tag 7")
	if strings.HasSuffix(line, "check-state") || strings.Contains(line, "check-state ") {
		return line
	}
	if rapid.IntRange(0, 3).Draw(t, "nativeBody") == 0 {
		if drawPick(t, "nativeComment", true, false) {
			return line + drawPick(t, "nativeInline", " //", " // c", " //x")
		}
		return line + " " + genOption(t)
	}
	line += " " + genProtocols(t)
	line += " from " + genTargets(t)
	if ports := genPorts(t); ports != "" {
		line += " " + ports
	}
	line += " to " + genTargets(t)
	if ports := genPorts(t); ports != "" {
		line += " " + ports
	}
	if options := genOptions(t); options != "" {
		line += " " + options
	}
	if drawPick(t, "comment", true, false) {
		line += drawPick(t, "inline", " // c", " //x", " // {\"id\": 1}")
	}
	return line
}

// genRulesetLine draws one valid line of any record kind.
func genRulesetLine(t *rapid.T) string {
	switch drawPick(t, "kind",
		"instruction", "instruction", "instruction", "label", "comment", "empty", "tableCreate", "tableAdd",
	) {
	case "label":
		return ":" + drawPick(t, "label", genLabels...)
	case "comment":
		return "#" + drawPick(t, "comment", " fw", "", " blockers")
	case "empty":
		return ""
	case "tableCreate":
		line := "table " + drawPick(t, "tableName", genTableNames...) + " create"
		if drawPick(t, "tableType", true, false) {
			line += " type " + drawPick(t, "type", "addr", "iface", "number", "flow", "mac")
		}
		return line
	case "tableAdd":
		line := "table " + drawPick(t, "tableName2", genTableNames...) + " add " +
			drawPick(t, "key", "192.0.2.0/24", "2001:db8::1", "vlan7")
		if drawPick(t, "value", true, false) {
			line += " " + drawPick(t, "tableValue", ":L", ":JUMP", "42")
		}
		return line
	default:
		return genInstructionLine(t)
	}
}

// verifies the central property: for a generated valid line the canonical
// text parses back into the same record and body and formats identically
// again.
func Test_Formatter_ParseEquivalence_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		parsed := parseOne(t, genInstructionLine(t))
		text, err := ipfw.NewFormatter().Record(parsed)
		require.NoError(t, err)

		reparsed := parseOne(t, text)
		expected := parsed.Record
		expected.Text = text
		require.Equal(t, expected, reparsed.Record)
		require.Equal(t, emptyToNil(parsed.Body), emptyToNil(reparsed.Body))
		require.Equal(t, parsed.BodyKind, reparsed.BodyKind)

		again, err := ipfw.NewFormatter().Record(reparsed)
		require.NoError(t, err)
		require.Equal(t, text, again)
	})
}

// verifies the ruleset property: a generated ruleset serializes in order,
// parses back record by record and body by body, and serializes to the
// same bytes again.
func Test_Formatter_RulesetRoundTrip_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		count := rapid.IntRange(1, 12).Draw(t, "lines")
		lines := make([]string, 0, count)
		for range count {
			lines = append(lines, genRulesetLine(t))
		}
		records := collectRuleset(t, strings.Join(lines, "\n")+"\n")
		require.Len(t, records, count)

		canonical, err := ipfw.NewFormatter().AppendRuleset(nil, records)
		require.NoError(t, err)
		reparsed := collectRuleset(t, string(canonical))
		require.Len(t, reparsed, count)
		canonicalLines := strings.Split(strings.TrimSuffix(string(canonical), "\n"), "\n")
		for idx := range records {
			expected := records[idx].Record
			expected.Line = idx + 1
			expected.Text = canonicalLines[idx]
			require.Equal(t, expected, reparsed[idx].Record)
			require.Equal(t, emptyToNil(records[idx].Body), emptyToNil(reparsed[idx].Body))
			require.Equal(t, records[idx].BodyKind, reparsed[idx].BodyKind)
		}

		again, err := ipfw.NewFormatter().AppendRuleset(nil, reparsed)
		require.NoError(t, err)
		require.Equal(t, string(canonical), string(again))
	})
}

// seedRNG turns fuzz bytes into every field of a record, one byte at a
// time.
type seedRNG struct {
	data []byte
	idx  int
}

func (m *seedRNG) byte() byte {
	m.idx = (m.idx + 1) % len(m.data)
	return m.data[m.idx]
}

func (m *seedRNG) bool() bool {
	return m.byte()%2 == 0
}

func (m *seedRNG) uint32() uint32 {
	return uint32(m.byte()) | uint32(m.byte())<<8 | uint32(m.byte())<<16 | uint32(m.byte())<<24
}

// seedAlphabet mixes plain name bytes with the delimiters and keywords that
// stress the validation.
const seedAlphabet = "abz019.-:/{},()`\\_# \tnotp"

func (m *seedRNG) text() string {
	text := make([]byte, m.byte()%12)
	for idx := range text {
		text[idx] = seedAlphabet[m.byte()%byte(len(seedAlphabet))]
	}
	return string(text)
}

func (m *seedRNG) maybeText() string {
	if m.bool() {
		return ""
	}
	return m.text()
}

// seedRecord builds a pseudo-random record from fuzz bytes, every public
// field reachable.
func seedRecord(seed []byte) ipfw.ParsedRecord {
	if record, ok := validSeedRecord(string(seed)); ok {
		return record
	}
	if len(seed) == 0 {
		seed = []byte{0}
	}
	rng := &seedRNG{data: seed}
	record := ipfw.ParsedRecord{
		Record:   ipfw.Record{Kind: ipfw.RecordKind(rng.byte() % 8)},
		BodyKind: ipfw.RuleBodyKind(rng.byte() % 4),
	}
	record.Record.Comment = rng.maybeText()
	record.Record.Label = rng.maybeText()
	record.Record.Table = ipfw.Table{
		Name:  rng.maybeText(),
		Kind:  ipfw.TableKind(rng.byte() % 4),
		Type:  ipfw.TableType(rng.byte() % 7),
		Key:   ipfw.TableKey{Kind: ipfw.TableKeyKind(rng.byte() % 5), Text: rng.maybeText()},
		Value: rng.maybeText(),
	}
	record.Record.Instruction = ipfw.Instruction{
		Num: rng.uint32(),
		Action: ipfw.Action{
			Kind: ipfw.ActionKind(rng.byte() % 7),
			Flow: rng.maybeText(),
			SkipTo: ipfw.SkipTo{
				Kind:   ipfw.SkipToKind(rng.byte() % 5),
				Label:  rng.maybeText(),
				Number: rng.uint32(),
			},
		},
		Log:           ipfw.Log{Enabled: rng.bool(), HasAmount: rng.bool(), Amount: rng.uint32()},
		Tag:           rng.uint32(),
		InlineComment: rng.maybeText(),
	}
	for range rng.byte() % 4 {
		if rng.bool() {
			record.Body.IPProtos = append(record.Body.IPProtos,
				ipfw.ProtoIPMatch{Neg: rng.bool(), Proto: ipfw.ProtoIP(rng.byte())})
		}
		if rng.bool() {
			record.Body.Protos = append(record.Body.Protos,
				ipfw.ProtoMatch{Neg: rng.bool(), Proto: ipfw.Proto{Name: rng.maybeText(), Number: rng.byte()}})
		}
		if rng.bool() {
			record.Body.Sources = append(record.Body.Sources, seedTarget(rng))
		}
		if rng.bool() {
			record.Body.Destinations = append(record.Body.Destinations, seedTarget(rng))
		}
		if rng.bool() {
			record.Body.SourcePorts = append(record.Body.SourcePorts, seedPortMatch(rng))
		}
		if rng.bool() {
			record.Body.DestinationPorts = append(record.Body.DestinationPorts, seedPortMatch(rng))
		}
		if rng.bool() {
			record.Body.Options = append(record.Body.Options, seedOpt(rng))
		}
	}
	return record
}

// validSeedRecord pins successful formatter paths in the fuzz baseline corpus.
func validSeedRecord(seed string) (ipfw.ParsedRecord, bool) {
	record := instructionRecord()
	switch seed {
	case "valid/negated-protocol-not":
		record.Body.IPProtos = nil
		record.Body.Protos = []ipfw.ProtoMatch{{Neg: true, Proto: ipfw.Proto{Name: "not"}}}
	case "valid/native-option":
		record.BodyKind = ipfw.RuleBodyNative
		record.Body.IPProtos = nil
		record.Body.Protos = nil
		record.Body.Options = []ipfw.Opt{{Kind: ipfw.OptIn}}
	case "valid/native-comment":
		record.BodyKind = ipfw.RuleBodyNative
		record.Body.IPProtos = nil
		record.Body.Protos = nil
		record.Record.Instruction.InlineComment = " memo"
	case "valid/comment-only":
		record.BodyKind = ipfw.RuleBodyCommentOnly
		record.Body.IPProtos = nil
		record.Body.Protos = nil
		record.Record.Instruction.Action = ipfw.Action{Kind: ipfw.ActionCount}
		record.Record.Instruction.InlineComment = " memo"
	case "valid/target-patterns":
		record.Body.Sources = []ipfw.Target{
			{Kind: ipfw.TargetAny},
			{Pattern: 1, Kind: ipfw.TargetMe},
		}
	case "valid/port-list-option":
		record.Body.Options = []ipfw.Opt{
			{Kind: ipfw.OptDestinationPort, Ports: portRangeNumber(22)},
			{
				Or:     true,
				PortOr: true,
				Kind:   ipfw.OptDestinationPort,
				Ports:  portRangeNumber(80),
			},
		}
	case "valid/tcpflags-overlap":
		record.Body.Options = []ipfw.Opt{tcpFlags(ipfw.TCPSyn, ipfw.TCPSyn)}
	case "valid/check-state-comment":
		record.Record.Instruction = ipfw.Instruction{
			Action:        ipfw.Action{Kind: ipfw.ActionCheckState},
			InlineComment: " cached",
		}
		record.Body = ipfw.ReduceState{}
	case "valid/table-hostname":
		record.Record.Kind = ipfw.RecordTable
		record.Record.Instruction = ipfw.Instruction{}
		record.Record.Table = ipfw.Table{
			Name: "hosts",
			Kind: ipfw.TableAdd,
			Key:  ipfw.TableKey{Kind: ipfw.TableKeyHostname, Text: "host.example.com"},
		}
		record.Body = ipfw.ReduceState{}
	default:
		return ipfw.ParsedRecord{}, false
	}
	return record, true
}

// seedTarget draws one pseudo-random target.
func seedTarget(rng *seedRNG) ipfw.Target {
	return ipfw.Target{
		Neg:     rng.bool(),
		Pattern: uint16(rng.byte()),
		Kind:    ipfw.TargetKind(rng.byte() % 9),
		Text:    rng.maybeText(),
	}
}

// seedPortMatch draws one pseudo-random port match.
func seedPortMatch(rng *seedRNG) ipfw.PortMatch {
	return ipfw.PortMatch{
		Neg: rng.bool(),
		Lo:  ipfw.Port{Name: rng.maybeText(), Number: uint16(rng.byte())<<8 | uint16(rng.byte())},
		Hi:  ipfw.Port{Name: rng.maybeText(), Number: uint16(rng.byte())<<8 | uint16(rng.byte())},
	}
}

// seedOpt draws one pseudo-random option.
func seedOpt(rng *seedRNG) ipfw.Opt {
	opt := ipfw.Opt{
		Neg:  rng.bool(),
		Or:   rng.bool(),
		Kind: ipfw.OptKind(rng.byte() % 18),
		Text: rng.maybeText(),
		Arg:  rng.maybeText(),
	}
	opt.Ports = ipfw.PortRange{
		Lo: ipfw.Port{Name: rng.maybeText(), Number: uint16(rng.byte())},
		Hi: ipfw.Port{Name: rng.maybeText(), Number: uint16(rng.byte())},
	}
	opt.Proto = ipfw.Proto{Name: rng.maybeText(), Number: rng.byte()}
	var types ipfw.TypeSet
	for range rng.byte() % 6 {
		types.Add(rng.byte())
	}
	opt.Types = types
	opt.TCPFlags = ipfw.TCPFlags{Set: ipfw.TCPFlag(rng.byte()), Clear: ipfw.TCPFlag(rng.byte())}
	opt.Via = ipfw.Via{Kind: ipfw.ViaKind(rng.byte() % 5), Name: rng.maybeText(), Value: rng.maybeText()}
	return opt
}

// fuzzRecordSeeds pin a few shapes the byte soup must reach.
var fuzzRecordSeeds = [][]byte{
	{0},
	{1, 2, 3, 4},
	{'p', 'a', 's', 's'},
	{'a', 'd', 'd', ' ', '1'},
	{0xff, 0xff, 0xff},
	{'1', '9', '2', '.', '0', '.', '2', '.', '1'},
	{':', 'L'},
	{'#', ' ', 'c'},
	[]byte("valid/negated-protocol-not"),
	[]byte("valid/native-option"),
	[]byte("valid/native-comment"),
	[]byte("valid/comment-only"),
	[]byte("valid/target-patterns"),
	[]byte("valid/port-list-option"),
	[]byte("valid/tcpflags-overlap"),
	[]byte("valid/check-state-comment"),
	[]byte("valid/table-hostname"),
}

// verifies that an arbitrary record either formats into text that parses
// back into the same record and body, or fails with a validation error,
// and never panics.
func Fuzz_Formatter_Record(f *testing.F) {
	for _, seed := range fuzzRecordSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed []byte) {
		record := seedRecord(seed)
		text, err := ipfw.NewFormatter().Record(record)
		if err != nil {
			return
		}
		var state ipfw.ReduceState
		rec, parseErr := ipfw.NewParser(text+"\n", ipfw.WithLabels()).Next(&state)
		require.Nilf(t, parseErr, "the canonical text %q must parse back", text)
		expected := record.Record
		expected.Line = 1
		expected.Text = text
		require.Equal(t, expected, *rec)
		require.Equal(t, emptyToNil(record.Body), emptyToNil(state))
		reparsed := ipfw.NewParsedRecord(rec, &state)
		require.Equal(t, record.BodyKind, reparsed.BodyKind)
	})
}

// verifies that every built-in parser output has a canonical formatter representation.
func Fuzz_Formatter_ParsedRecord(f *testing.F) {
	f.Add("add pass ip from any to any\n")
	f.Add("add 110 allow in\n")
	f.Add("add count //x\n")
	f.Add("add // memo\n")
	f.Add("table t create type addr\n")
	f.Add(":LABEL\n")
	f.Fuzz(func(t *testing.T, input string) {
		var state ipfw.ReduceState
		record, parseErr := ipfw.NewParser(input, ipfw.WithLabels()).Next(&state)
		if parseErr != nil || record.Kind == ipfw.RecordEOF {
			return
		}
		parsed := ipfw.NewParsedRecord(record, &state)
		text, err := ipfw.NewFormatter().Record(parsed)
		require.NoError(t, err)

		reparsed := parseOne(t, text)
		expected := parsed.Record
		expected.Line = 1
		expected.Text = text
		require.Equal(t, expected, reparsed.Record)
		require.Equal(t, emptyToNil(parsed.Body), emptyToNil(reparsed.Body))
		require.Equal(t, parsed.BodyKind, reparsed.BodyKind)
	})
}

// verifies that formatting into a destination with enough capacity
// allocates nothing, record by record and as a whole ruleset.
func Test_Formatter_Append_NoAllocs(t *testing.T) {
	// A slice of the synthetic ruleset, small enough to leave the heap
	// quiet for the allocation guards that run after this test.
	lines := strings.Split(syntheticRuleset(), "\n")
	src := strings.Join(lines[:min(len(lines), 500)], "\n") + "\n"
	records := collectRuleset(t, src)
	formatter := ipfw.NewFormatter()

	canonical, err := formatter.AppendRuleset(nil, records)
	require.NoError(t, err)
	lineLen := 0
	for line := range strings.SplitSeq(string(canonical), "\n") {
		lineLen = max(lineLen, len(line))
	}

	ok := true
	buf := make([]byte, 0, lineLen+1)
	allocs := testing.AllocsPerRun(100, func() {
		for idx := range records {
			var err error
			buf, err = formatter.AppendRecord(buf[:0], records[idx])
			if err != nil {
				ok = false
			}
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)

	ok = true
	whole := make([]byte, 0, len(canonical))
	allocs = testing.AllocsPerRun(100, func() {
		var err error
		whole, err = formatter.AppendRuleset(whole[:0], records)
		if err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
	require.Len(t, whole, len(canonical))
}

// The benchmark results are sunk here so the compiler keeps the work.
var (
	benchText    []byte
	benchFmtErr  error
	benchRecords []ipfw.ParsedRecord
)

func Benchmark_Formatter_AppendRecord_SimpleRule(b *testing.B) {
	record := parseOne(b, "add 100 deny log logamount 5 tag 7 tcp from 192.0.2.0/24 1024-65535 to any 22 in")
	formatter := ipfw.NewFormatter()
	line, err := formatter.Record(record)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 0, len(line))
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for b.Loop() {
		buf, benchFmtErr = formatter.AppendRecord(buf[:0], record)
		benchText = buf
	}
}

func Benchmark_Formatter_AppendRuleset_Synthetic(b *testing.B) {
	var state ipfw.ReduceState
	parser := ipfw.NewParser(syntheticRuleset(), ipfw.WithLabels())
	for {
		state.Reset()
		rec, err := parser.Next(&state)
		if err != nil {
			b.Fatal(err)
		}
		if rec.Kind == ipfw.RecordEOF {
			break
		}
		benchRecords = append(benchRecords, ipfw.NewParsedRecord(rec, &state))
	}
	formatter := ipfw.NewFormatter()
	canonical, err := formatter.AppendRuleset(nil, benchRecords)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 0, len(canonical))
	b.SetBytes(int64(len(canonical)))
	b.ReportAllocs()
	for b.Loop() {
		buf, benchFmtErr = formatter.AppendRuleset(buf[:0], benchRecords)
		benchText = buf
	}
}

func ExampleFormatter_AppendRuleset() {
	src := "# blocking rules below\n" +
		"add 100 skipto :trusted ip from table(_BLOCK_) to any\n" +
		":trusted\n" +
		"add   allow log tcp from any to 192.0.2.0/24  443\n"
	parser := ipfw.NewParser(src, ipfw.WithLabels())
	var state ipfw.ReduceState
	var records []ipfw.ParsedRecord
	for {
		rec, err := parser.Next(&state)
		if err != nil {
			fmt.Println(ipfw.NewDiag(err))
			return
		}
		if rec.Kind == ipfw.RecordEOF {
			break
		}
		records = append(records, ipfw.NewParsedRecord(rec, &state))
		state.Reset()
	}
	text, err := ipfw.NewFormatter().AppendRuleset(nil, records)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Print(string(text))
	// Output:
	// # blocking rules below
	// add 100 skipto :trusted ip from table(_BLOCK_) to any
	// :trusted
	// add pass log tcp from any to 192.0.2.0/24 443
}
