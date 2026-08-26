// Package ipfw parses the FreeBSD/macOS ipfw(8) ruleset format.
//
// The parser is streaming and zero-copy: the input is a single string and
// every emitted token is a sub-slice of it. It works in layers. The Parser
// reads one line at a time, returns a Record for the line (an instruction, a
// table command, a label or a comment) and pushes the rule body — protocols,
// source and destination targets, ports, options — as raw string tokens into
// a State. RuleState is the State implementation that turns those tokens into
// typed values with pluggable network types and name resolution. Package vm
// compiles the stream into a rule set and evaluates packets against it.
//
// The format is documented in https://man.freebsd.org/cgi/man.cgi?ipfw(8).
package ipfw
