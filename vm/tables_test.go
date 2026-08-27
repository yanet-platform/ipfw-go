package vm_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"

	"github.com/yanet-platform/ipfw/vm"
)

var _ vm.TableRegistry[net4, net6] = (*vm.DefaultTables[net4, net6])(nil)

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

// verifies that a network lookup finds an address in any network of the
// table's family and nothing in a missing or empty table.
func Test_Tables_LookupNetwork(t *testing.T) {
	tables := vm.NewDefaultTables[net4, net6]()
	tables.AddNetwork4("t", must4(t, "192.0.2.0/24"))
	tables.AddNetwork4("t", must4(t, "198.51.100.0/25"))
	tables.AddNetwork6("t", must6(t, "2001:db8::/32"))
	tables.AddInterface("empty", "vlan1", "")

	require.True(t, tables.LookupNetwork("t", netip.MustParseAddr("192.0.2.1")))
	require.True(t, tables.LookupNetwork("t", netip.MustParseAddr("198.51.100.127")))
	require.False(t, tables.LookupNetwork("t", netip.MustParseAddr("198.51.100.128")))
	require.True(t, tables.LookupNetwork("t", netip.MustParseAddr("2001:db8:ffff::1")))
	require.False(t, tables.LookupNetwork("t", netip.MustParseAddr("2001:db9::1")))
	require.False(t, tables.LookupNetwork("missing", netip.MustParseAddr("192.0.2.1")))
	require.False(t, tables.LookupNetwork("empty", netip.MustParseAddr("192.0.2.1")))
}

// verifies that an interface lookup yields the value of the exact name and
// nothing for another name or a missing table.
func Test_Tables_LookupInterface(t *testing.T) {
	tables := vm.NewDefaultTables[net4, net6]()
	tables.AddInterface("i", "vlan1", "LABEL")
	tables.AddInterface("i", "vlan2", "")
	tables.AddInterface("i", "vlan1", "AGAIN")
	tables.AddNetwork4("nets", must4(t, "192.0.2.0/24"))

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
	tables := vm.NewDefaultTables[net4, net6]()
	tables.AddNetwork4("t", must4(t, "192.0.2.0/24"))
	tables.AddNetwork6("t", must6(t, "2001:db8::/32"))
	tables.AddInterface("i", "vlan1", "LABEL")
	addr4, addr6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	hits := 0
	allocs := testing.AllocsPerRun(100, func() {
		if tables.LookupNetwork("t", addr4) {
			hits++
		}
		if tables.LookupNetwork("t", addr6) {
			hits++
		}
		if _, ok := tables.LookupInterface("i", "vlan1"); ok {
			hits++
		}
	})
	require.Equal(t, 303, hits)
	require.Zero(t, allocs)
}
