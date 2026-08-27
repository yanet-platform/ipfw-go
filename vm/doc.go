// Package vm evaluates packets against a parsed ipfw(8) ruleset.
//
// Build reads a ruleset from an ipfw.Parser into a VM, resolving every name
// within the Environment of its Config on the way in. Check runs a packet
// through the rules in order, in the Context of the check (direction,
// interface, the host's own addresses), and returns the verdict of the
// first pass or deny rule that matches, or the configured default verdict
// when none does. Skips are followed, count and check-state go on, and
// options are folded as ipfw(8) reads them. The VM is stateless and a
// check allocates nothing.
package vm
