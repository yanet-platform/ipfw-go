package ipfw_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// allowFromAny is a command hook for `ALLOW_FROM_ANY(PROTO, DST[, PORTS])
// [// comment]`, a syntax the parser does not know.
//
// It reduces the line to a pass rule from any with the exported
// sub-parsers.
func allowFromAny(line string, state ipfw.State) (ipfw.Record, int, error) {
	const keyword = "ALLOW_FROM_ANY("
	if !strings.HasPrefix(line, keyword) {
		return ipfw.Record{}, 0, nil
	}
	pos := len(keyword)
	n, err := ipfw.ParseProtocols(line[pos:], state)
	if err != nil {
		return ipfw.Record{}, pos + n, err
	}
	pos += n
	if !strings.HasPrefix(line[pos:], ",") {
		return ipfw.Record{}, pos, ipfw.ErrExpectedPrefix
	}
	pos = skipSpaces(line, pos+1)
	if rejected := state.OnSourceTarget(ipfw.Target{Kind: ipfw.TargetAny}); rejected != nil {
		return ipfw.Record{}, pos, rejected
	}
	n, err = ipfw.ParseDestinationTargets(line[pos:], state)
	if err != nil {
		return ipfw.Record{}, pos + n, err
	}
	pos += n
	if strings.HasPrefix(line[pos:], ",") {
		pos = skipSpaces(line, pos+1)
		n, err = ipfw.ParseDestinationPorts(line[pos:], state)
		if err != nil {
			return ipfw.Record{}, pos + n, err
		}
		pos += n
	}
	if !strings.HasPrefix(line[pos:], ")") {
		return ipfw.Record{}, pos, ipfw.ErrExpectedPrefix
	}
	pos++
	rec := ipfw.Record{
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}
	if rest := skipSpaces(line, pos); strings.HasPrefix(line[rest:], "//") {
		rec.Instruction.InlineComment = line[rest+2:]
		pos = len(line)
	}
	return rec, pos, nil
}

// skipSpaces returns the offset of the first byte after the spaces at pos.
func skipSpaces(line string, pos int) int {
	for pos < len(line) && (line[pos] == ' ' || line[pos] == '\t') {
		pos++
	}
	return pos
}

// swallowing is a command hook that consumes an `IGNORE …` line without a
// record.
func swallowing(line string, _ ipfw.State) (ipfw.Record, int, error) {
	if !strings.HasPrefix(line, "IGNORE") {
		return ipfw.Record{}, 0, nil
	}
	return ipfw.Record{}, len(line), nil
}

// verifies that a command hook takes over a line the parser does not know
// and that the parser still ends the line itself.
//
// The record is completed with the position, the state is filled by the
// sub-parsers the hook calls.
func Test_CommandHook_Table(t *testing.T) {
	pass := ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}}
	cases := []struct {
		name        string
		input       string
		instruction ipfw.Instruction
		state       ipfw.ReduceState
	}{
		{
			name:        "protocol, group and range",
			input:       "ALLOW_FROM_ANY(tcp, { _VPN_LOOPBACKS_ }, 1-65535)\n",
			instruction: pass,
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations:     []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "_VPN_LOOPBACKS_"}},
				DestinationPorts: []ipfw.PortMatch{portSpan(ipfw.Port{Number: 1}, ipfw.Port{Number: 65535})},
			},
		},
		{
			name:  "port list and inline comment",
			input: "ALLOW_FROM_ANY(udp, { _CDN_NETS_ }, 80,443) // {\"id\": 1}\n",
			instruction: ipfw.Instruction{
				Action:        ipfw.Action{Kind: ipfw.ActionPass},
				InlineComment: " {\"id\": 1}",
			},
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "udp"}}},
				Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations:     []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "_CDN_NETS_"}},
				DestinationPorts: []ipfw.PortMatch{portNumber(80), portNumber(443)},
			},
		},
		{
			name:        "no ports",
			input:       "ALLOW_FROM_ANY(esp, { _X_ })\n",
			instruction: pass,
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "esp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "_X_"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input, ipfw.WithCommandHook(allowFromAny)).Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line:        1,
				Text:        strings.TrimSuffix(tc.input, "\n"),
				Kind:        ipfw.RecordInstruction,
				Instruction: tc.instruction,
			}, *rec)
			require.Equal(t, tc.state, state)
		})
	}
}

// verifies that a hook consuming a line without a record yields an empty
// record for it, the next line parsing as usual.
func Test_CommandHook_Swallowed(t *testing.T) {
	parser := ipfw.NewParser("IGNORE this line\nadd pass ip from any to any\n", ipfw.WithCommandHook(swallowing))
	next(t, parser, ipfw.Record{Line: 1, Text: "IGNORE this line", Kind: ipfw.RecordEmpty})
	var state ipfw.ReduceState
	rec, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(2, "add pass ip from any to any"), *rec)
	require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
}

// verifies the failures around a command hook.
//
// Trailing content after what it consumed, its own errors positioned where
// it says, an unhandled line, and no hook at all.
func Test_CommandHook_Errors(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name     string
		input    string
		hook     ipfw.CommandHook
		expected ipfw.ParseError
	}{
		{
			name:  "trailing content after the hook",
			input: "ALLOW_FROM_ANY(esp, { _X_ }) x\n",
			hook:  allowFromAny,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 29,
				Text:   "ALLOW_FROM_ANY(esp, { _X_ }) x",
			},
		},
		{
			name:  "error kind from the hook",
			input: "ALLOW_FROM_ANY(esp { _X_ })\n",
			hook:  allowFromAny,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedPrefix,
				Line:   1,
				Column: 18,
				Text:   "ALLOW_FROM_ANY(esp { _X_ })",
			},
		},
		{
			name:  "error kind at a chosen offset",
			input: "CUSTOM line\n",
			hook: func(string, ipfw.State) (ipfw.Record, int, error) {
				return ipfw.Record{}, 5, ipfw.ErrExpectedCommand
			},
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedCommand,
				Line:   1,
				Column: 5,
				Text:   "CUSTOM line",
			},
		},
		{
			name:  "plain error from the hook",
			input: "CUSTOM line\n",
			hook: func(string, ipfw.State) (ipfw.Record, int, error) {
				return ipfw.Record{}, 5, boom
			},
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrState,
				Err:    boom,
				Line:   1,
				Column: 5,
				Text:   "CUSTOM line",
			},
		},
		{
			name:  "line the hook does not handle",
			input: "CUSTOM line\n",
			hook:  allowFromAny,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedLine,
				Line:   1,
				Column: 0,
				Text:   "CUSTOM line",
			},
		},
		{
			name:  "no hook",
			input: "ALLOW_FROM_ANY(esp, { _X_ })\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedLine,
				Line:   1,
				Column: 0,
				Text:   "ALLOW_FROM_ANY(esp, { _X_ })",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var options []ipfw.ParserOption
			if tc.hook != nil {
				options = append(options, ipfw.WithCommandHook(tc.hook))
			}
			nextError(t, ipfw.NewParser(tc.input, options...), tc.expected)
		})
	}
}

// verifies that a line handled by a hook built from the sub-parsers parses
// into a warmed-up state without allocating.
func Test_CommandHook_NoAllocs(t *testing.T) {
	src := "ALLOW_FROM_ANY(tcp, { _VPN_LOOPBACKS_ }, 1-65535)\n"
	parser := ipfw.NewParser(src, ipfw.WithCommandHook(allowFromAny))
	var state ipfw.ReduceState
	_, _ = parser.Next(&state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		state.Reset()
		if _, err := parser.Next(&state); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}

// customOptions is an option hook for two options the grammar does not
// know: the keyword `setup` and `uid NAME`.
func customOptions(rest string) (ipfw.Opt, int, error) {
	if strings.HasPrefix(rest, "setup") {
		return ipfw.Opt{Kind: ipfw.OptCustom, Text: "setup"}, len("setup"), nil
	}
	if strings.HasPrefix(rest, "uid ") {
		name := rest[len("uid "):]
		if end := strings.IndexAny(name, " \t\n}"); end >= 0 {
			name = name[:end]
		}
		if name == "" {
			return ipfw.Opt{}, len("uid "), ipfw.ErrExpectedOpt
		}
		return ipfw.Opt{Kind: ipfw.OptCustom, Text: "uid", Arg: name}, len("uid ") + len(name), nil
	}
	return ipfw.Opt{}, 0, nil
}

// verifies that an option hook takes the keywords the grammar does not
// know in every place an option can stand.
//
// The parser adds the negation and the or-flag, and the hook takes part in
// the option-versus-port precedence.
func Test_OptionHook_Table(t *testing.T) {
	anyToAny := []ipfw.Target{{Kind: ipfw.TargetAny}}
	tcp := []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}}
	setup := ipfw.Opt{Kind: ipfw.OptCustom, Text: "setup"}
	cases := []struct {
		name    string
		input   string
		options []ipfw.Opt
	}{
		{
			name:    "keyword then a known option",
			input:   "add allow tcp from any to any setup in\n",
			options: []ipfw.Opt{setup, {Kind: ipfw.OptIn}},
		},
		{
			name:    "keyword in a group",
			input:   "add allow tcp from any to any { setup or in }\n",
			options: []ipfw.Opt{setup, {Or: true, Kind: ipfw.OptIn}},
		},
		{
			name:    "negated keyword",
			input:   "add allow tcp from any to any not setup\n",
			options: []ipfw.Opt{notOpt(setup)},
		},
		{
			name:    "option with an argument",
			input:   "add allow tcp from any to any uid root established\n",
			options: []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "uid", Arg: "root"}, {Kind: ipfw.OptEstablished}},
		},
		{
			name:    "keyword alone is an option, not a port",
			input:   "add allow tcp from any to any setup\n",
			options: []ipfw.Opt{setup},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input, ipfw.WithOptionHook(customOptions)).Next(&state)
			require.Nil(t, err)
			require.Equal(t, passAnyToAny(1, strings.TrimSuffix(tc.input, "\n")), *rec)
			require.Equal(t, ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      tc.options,
			}, state)
		})
	}
}

// verifies that the hook is consulted for unknown keywords only.
func Test_OptionHook_Precedence(t *testing.T) {
	calls := 0
	counting := func(rest string) (ipfw.Opt, int, error) {
		calls++
		return customOptions(rest)
	}
	_, err := ipfw.NewParser("add allow tcp from any to any in established\n", ipfw.WithOptionHook(counting)).
		Next(ipfw.DiscardState{})
	require.Nil(t, err)
	require.Equal(t, 0, calls)

	_, err = ipfw.NewParser("add allow tcp from any to any setup\n", ipfw.WithOptionHook(counting)).
		Next(ipfw.DiscardState{})
	require.Nil(t, err)
	require.Positive(t, calls)
}

// verifies the failures around an option hook.
//
// A declined token is an unknown option, a hook error is positioned at the
// bytes it consumed, an ErrorKind keeping its kind and anything else
// becoming an ErrState.
func Test_OptionHook_Errors(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name     string
		input    string
		hook     ipfw.OptionHook
		expected ipfw.ParseError
	}{
		{
			name:  "declined token",
			input: "add allow tcp from any to any established foo",
			hook:  customOptions,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 42,
				Text:   "add allow tcp from any to any established foo",
			},
		},
		{
			name:  "error kind from the hook",
			input: "add allow tcp from any to any established uid \n",
			hook:  customOptions,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOpt,
				Line:   1,
				Column: 45,
				Text:   "add allow tcp from any to any established uid",
			},
		},
		{
			name:  "plain error from the hook",
			input: "add allow tcp from any to any established zz",
			hook: func(string) (ipfw.Opt, int, error) {
				return ipfw.Opt{}, 2, boom
			},
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrState,
				Err:    boom,
				Line:   1,
				Column: 44,
				Text:   "add allow tcp from any to any established zz",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input, ipfw.WithOptionHook(tc.hook)), tc.expected)
		})
	}
}

// verifies that the exported option parser passes the hook through.
func Test_ParseOptions_Hook(t *testing.T) {
	var state ipfw.ReduceState
	n, err := ipfw.ParseOptions("setup in", &state, customOptions)
	require.NoError(t, err)
	require.Equal(t, 8, n)
	require.Equal(t, ipfw.ReduceState{
		Options: []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "setup"}, {Kind: ipfw.OptIn}},
	}, state)
}

// verifies that a line with custom options parses into a warmed-up state
// without allocating.
func Test_OptionHook_NoAllocs(t *testing.T) {
	src := "add allow tcp from any to any uid root { setup or in } established\n"
	parser := ipfw.NewParser(src, ipfw.WithOptionHook(customOptions))
	var state ipfw.ReduceState
	_, _ = parser.Next(&state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		state.Reset()
		if _, err := parser.Next(&state); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
