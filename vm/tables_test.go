package vm_test

import (
	"fmt"
	"net/netip"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"

	"github.com/yanet-platform/ipfw-go/vm"
)

var _ vm.TableRegistry[net4, net6] = (*vm.DefaultTableRegistry[net4, net6])(nil)

// must4 parses an IPv4 network or fails the test.
func must4(t *testing.T, s string) net4 {
	t.Helper()
	network, err := xnetip.ParseNetwork4(s)
	require.NoError(t, err)
	return network
}

// must6 parses an IPv6 network or fails the test.
func must6(t *testing.T, s string) net6 {
	t.Helper()
	network, err := xnetip.ParseNetwork6(s)
	require.NoError(t, err)
	return network
}

// verifies that a network lookup yields the value of a network of the
// address's family holding it, and nothing in a missing or empty table.
func Test_Tables_LookupNetwork(t *testing.T) {
	tables := vm.NewDefaultTableRegistry[net4, net6]()
	tables.AddNetwork4("t", must4(t, "192.0.2.0/24"), "100")
	tables.AddNetwork4("t", must4(t, "198.51.100.0/25"), "")
	tables.AddNetwork6("t", must6(t, "2001:db8::/32"), "SIX")
	tables.AddInterface("empty", "vlan1", "")

	cases := []struct {
		name  string
		table string
		addr  string
		value string
		ok    bool
	}{
		{name: "IPv4 network", table: "t", addr: "192.0.2.1", value: "100", ok: true},
		{name: "empty value", table: "t", addr: "198.51.100.127", ok: true},
		{name: "past the network", table: "t", addr: "198.51.100.128"},
		{name: "IPv6 network", table: "t", addr: "2001:db8:ffff::1", value: "SIX", ok: true},
		{name: "IPv6 miss", table: "t", addr: "2001:db9::1"},
		{name: "IPv4-mapped IPv6", table: "t", addr: "::ffff:192.0.2.1"},
		{name: "missing table", table: "missing", addr: "192.0.2.1"},
		{name: "interface table", table: "empty", addr: "192.0.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, ok := tables.LookupNetwork(tc.table, netip.MustParseAddr(tc.addr))
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.value, value)
		})
	}
}

// verifies that of the networks holding an address the one with the fewest
// host bits decides whatever the order added, the last added among equal ones.
func Test_Tables_LookupNetwork_LongestPrefix(t *testing.T) {
	tables := vm.NewDefaultTableRegistry[net4, net6]()
	tables.AddNetwork4("t", must4(t, "192.0.2.128/25"), "HALF")
	tables.AddNetwork4("t", must4(t, "0.0.0.0/0"), "DEFAULT")
	tables.AddNetwork4("t", must4(t, "192.0.2.0/24"), "NET")
	tables.AddNetwork4("t", must4(t, "192.0.2.200/32"), "HOST")
	tables.AddNetwork4("t", must4(t, "192.0.2.128/25"), "AGAIN")
	tables.AddNetwork6("t", must6(t, "2001:db8::/32"), "NET6")
	tables.AddNetwork6("t", must6(t, "2001:db8:1::/48"), "SITE6")

	cases := []struct {
		addr  string
		value string
	}{
		{addr: "192.0.2.1", value: "NET"},
		{addr: "192.0.2.129", value: "AGAIN"},
		{addr: "192.0.2.200", value: "HOST"},
		{addr: "198.51.100.1", value: "DEFAULT"},
		{addr: "2001:db8:1::1", value: "SITE6"},
		{addr: "2001:db8:2::1", value: "NET6"},
	}
	for _, tc := range cases {
		value, ok := tables.LookupNetwork("t", netip.MustParseAddr(tc.addr))
		require.True(t, ok, tc.addr)
		require.Equal(t, tc.value, value, tc.addr)
	}
}

// verifies that an interface lookup yields the value of the exact name and
// nothing for another name or a missing table.
func Test_Tables_LookupInterface(t *testing.T) {
	tables := vm.NewDefaultTableRegistry[net4, net6]()
	tables.AddInterface("i", "vlan1", "LABEL")
	tables.AddInterface("i", "vlan2", "")
	tables.AddInterface("i", "vlan1", "AGAIN")
	tables.AddNetwork4("nets", must4(t, "192.0.2.0/24"), "")

	value, ok := tables.LookupInterface("i", "vlan1")
	require.True(t, ok)
	require.Equal(t, "AGAIN", value)
	value, ok = tables.LookupInterface("i", "vlan2")
	require.True(t, ok)
	require.Empty(t, value)
	_, ok = tables.LookupInterface("i", "vlan")
	require.False(t, ok)
	_, ok = tables.LookupInterface("nets", "vlan1")
	require.False(t, ok)
	_, ok = tables.LookupInterface("missing", "vlan1")
	require.False(t, ok)
}

// verifies that lookups allocate nothing.
func Test_Tables_NoAllocs(t *testing.T) {
	tables := vm.NewDefaultTableRegistry[net4, net6]()
	tables.AddNetwork4("t", must4(t, "192.0.2.0/24"), "NET")
	tables.AddNetwork4("t", must4(t, "192.0.2.0/25"), "HALF")
	tables.AddNetwork6("t", must6(t, "2001:db8::/32"), "NET6")
	tables.AddInterface("i", "vlan1", "LABEL")
	addr4, addr6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	hits := 0
	allocs := testing.AllocsPerRun(100, func() {
		if _, ok := tables.LookupNetwork("t", addr4); ok {
			hits++
		}
		if _, ok := tables.LookupNetwork("t", addr6); ok {
			hits++
		}
		if _, ok := tables.LookupInterface("i", "vlan1"); ok {
			hits++
		}
	})
	require.Equal(t, 303, hits)
	require.Zero(t, allocs)
}

// Benchmark_Tables_LookupNetwork measures lookups in a table of 128 hosts per
// family inside one wider network: a host, an address only the wide network
// holds, and a miss.
func Benchmark_Tables_LookupNetwork(b *testing.B) {
	tables := vm.NewDefaultTableRegistry[net4, net6]()
	for idx := range 128 {
		tables.AddNetwork4("t", parse4(fmt.Sprintf("192.0.2.%d/32", idx)), strconv.Itoa(idx))
		tables.AddNetwork6("t", parse6(fmt.Sprintf("2001:db8::%x/128", idx)), strconv.Itoa(idx))
	}
	tables.AddNetwork4("t", parse4("192.0.2.0/24"), "WIDE")
	tables.AddNetwork6("t", parse6("2001:db8::/32"), "WIDE")
	cases := []struct {
		name string
		addr string
	}{
		{name: "host4", addr: "192.0.2.64"},
		{name: "wide4", addr: "192.0.2.200"},
		{name: "miss4", addr: "203.0.113.1"},
		{name: "host6", addr: "2001:db8::40"},
		{name: "wide6", addr: "2001:db8::1:0"},
		{name: "miss6", addr: "2001:db9::1"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			addr := netip.MustParseAddr(tc.addr)
			b.ReportAllocs()
			for b.Loop() {
				tables.LookupNetwork("t", addr)
			}
		})
	}
}
