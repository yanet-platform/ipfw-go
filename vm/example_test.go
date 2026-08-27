package vm_test

import (
	"fmt"
	"net/netip"

	"github.com/yanet-platform/xnetip"

	"github.com/yanet-platform/ipfw"
	"github.com/yanet-platform/ipfw/vm"
)

// protocols resolves the protocol names a ruleset uses.
type protocols map[string]uint8

// ResolveProto implements ipfw.ProtoResolver.
func (m protocols) ResolveProto(name string) (uint8, bool) {
	number, ok := m[name]
	return number, ok
}

// printTracer prints every rule a check evaluates and whether it matched.
type printTracer struct{}

// Trace implements vm.Tracer.
func (printTracer) Trace(rec *ipfw.Record, _ ipfw.Action, matched bool) {
	mark := "-"
	if matched {
		mark = "+"
	}
	fmt.Printf("%d: %s %s\n", rec.Line, mark, rec.Text)
}

func ExampleVM_CheckTrace() {
	ruleset := "add deny ip from 198.51.100.0/24 to any\n" +
		"add pass tcp from 192.0.2.0/24 to any 22 in\n" +
		"add deny ip from any to any\n"
	machine, err := vm.Build(ipfw.NewParser(ruleset), vm.Config[xnetip.Network4, xnetip.Network6]{
		Environment: ipfw.Environment[xnetip.Network4, xnetip.Network6]{
			Networks: ipfw.NetworkParserFuncs[xnetip.Network4, xnetip.Network6]{
				Parse4:    xnetip.ParseNetwork4,
				Parse6:    xnetip.ParseNetwork6,
				FromAddr4: xnetip.Network4FromAddr,
				FromAddr6: xnetip.Network6FromAddr,
			},
			Protos: protocols{"tcp": 6, "udp": 17},
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	packet := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.1")).
		WithTCP(ipfw.TCPSyn, 40000, 22)
	ctx := &vm.Context{Direction: vm.In, IfName: "eth0"}
	action, matched := machine.CheckTrace(ctx, packet, printTracer{})
	fmt.Println(action, matched)
	// Output:
	//
	// 1: - add deny ip from 198.51.100.0/24 to any
	// 2: + add pass tcp from 192.0.2.0/24 to any 22 in
	// pass true
}
