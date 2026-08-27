// Package synthetic generates the deterministic ruleset the tests and the
// benchmarks of both packages share.
//
// Only tests import it, no runtime code depends on it.
package synthetic

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
)

// Ruleset is a ruleset of about ten thousand lines mixing every syntax form,
// the same on every call.
//
// Its jumps mostly go nowhere, so a VM built from it needs the fall-through
// policy, and its hostnames and macros a target resolver.
func Ruleset() string {
	return ruleset()
}

var ruleset = sync.OnceValue(func() string {
	random := rand.New(rand.NewPCG(1, 2))
	pick := func(choices ...string) string {
		return choices[random.IntN(len(choices))]
	}
	var b strings.Builder
	for idx := range 10000 {
		switch random.IntN(20) {
		case 0:
			fmt.Fprintf(&b, "table _T%d_ create type %s\n", idx%8, pick("iface", "addr"))
		case 1:
			fmt.Fprintf(&b, "table _T%d_ add %s\n", idx%8, pick(
				"192.0.2.0/24", "2001:db8::/48 :L", "vlan7 :JUMP", "198.51.100.1",
			))
		case 2:
			fmt.Fprintf(&b, ":LABEL_%d\n", idx)
		case 3:
			fmt.Fprintf(&b, "# rule %d of the synthetic set\n", idx)
		case 4:
			b.WriteString("\n")
		case 5:
			fmt.Fprintf(&b, "add %d check-state%s\n", idx, pick("", " :flow", " log"))
		default:
			b.WriteString("add ")
			if random.IntN(2) == 0 {
				fmt.Fprintf(&b, "%d ", idx)
			}
			b.WriteString(pick("pass", "deny", "count", "skipto :LABEL_1", "skipto 100"))
			b.WriteString(pick("", " log", " log logamount 50", " tag 3"))
			b.WriteString(pick(" ip", " tcp", " udp", " icmp", " { tcp or udp }", " not tcp"))
			b.WriteString(" from ")
			b.WriteString(pick(
				"any", "me", "192.0.2.0/24", "2001:db8::/32", "host.example.com",
				"table(_T1_)", "{ 192.0.2.1 or ::1 or me6 }", "not 198.51.100.0/24", "_MACRO_",
			))
			b.WriteString(pick("", "", " 22", " 1024-65535", " 22,80,443", " not 22"))
			b.WriteString(" to ")
			b.WriteString(pick(
				"any", "me6", "203.0.113.0/24", "2001:db8:1::/48", "`node-1.example.net'",
				"table(_T2_)", "{ any or table(_T3_) }", "not 192.0.2.128/25",
			))
			b.WriteString(pick("", "", " 80", " 1-65535", " 53,443"))
			b.WriteString(pick(
				"", "", " in", " out", " established", " keep-state :flow", " proto tcp",
				" tcpflags syn,!ack", " dst-port 8080,8443", " src-port 1024-65535",
				" via vlan1??", " via table(_T4_)", " icmptypes 0,8", " { in or out }",
				" not diverted", " antispoof", " frag", " in via eth0 established",
			))
			b.WriteString(pick("", "", " // {\"id\": 1}"))
			b.WriteString("\n")
		}
	}
	return b.String()
})
