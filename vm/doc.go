// Package vm evaluates packets against a parsed ipfw(8) ruleset.
//
// A VM is built from an ipfw.Parser and a network type parser; Check runs a
// packet through the rules in order and returns the verdict of the first
// terminating rule, or the configured default verdict when nothing matches.
package vm
