// Package ipfw parses the FreeBSD/macOS ipfw(8) ruleset format.
//
// The parser is streaming and zero-copy: the input is one string and every
// token it emits is a sub-slice of it. It works in layers.
//
//	string ──► Parser ──► State (raw string tokens), one Record per line
//	              │
//	              └─► Record: Instruction | Table | Label | Comment | Empty
//
//	Resolver[V4, V6]  implements State: resolves every name within an
//	                  Environment and hands typed tokens to a VMState
//	ReduceVMState     collects the typed tokens, ReduceState the raw ones
//
// The Parser reads one line at a time, returns the Record of the line and
// pushes the rule body, protocols, source and destination targets, ports and
// options, as raw tokens into a State. A Resolver is the State that turns
// names into values, networks with the consumer's own types, protocols and
// services into numbers, hostnames and macros into networks, and forwards
// them to a VMState, which is what package vm consumes to evaluate packets.
//
// The format is documented in https://man.freebsd.org/cgi/man.cgi?ipfw(8).
package ipfw
