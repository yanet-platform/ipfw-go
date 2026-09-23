package vm

import (
	"cmp"
	"net/netip"
	"slices"
)

// DefaultTableRegistry is the registry a build fills when the Config
// names none.
//
// An address lookup yields the value of the most specific network holding
// the address, the one with the fewest host bits, as the radix tables of
// ipfw(8) do. Of equally specific networks the last added wins, as ipfw -q
// updates an entry added again. Interfaces are looked up by exact name.
type DefaultTableRegistry[V4, V6 Network] struct {
	networks   map[string]*networkTable[V4, V6]
	interfaces map[string]map[string]string
}

// networkTable holds the networks of one table by family.
type networkTable[V4, V6 Network] struct {
	// V4 are the IPv4 networks.
	V4 prefixTable[V4]
	// V6 are the IPv6 networks.
	V6 prefixTable[V6]
}

// NewDefaultTableRegistry returns an empty registry.
func NewDefaultTableRegistry[V4, V6 Network]() *DefaultTableRegistry[V4, V6] {
	return &DefaultTableRegistry[V4, V6]{
		networks:   map[string]*networkTable[V4, V6]{},
		interfaces: map[string]map[string]string{},
	}
}

// LookupNetwork implements TableRegistry.
func (m *DefaultTableRegistry[V4, V6]) LookupNetwork(table string, addr netip.Addr) (string, bool) {
	networks, ok := m.networks[table]
	if !ok {
		return "", false
	}
	if addr.Is4() {
		return networks.V4.Lookup(addr)
	}
	return networks.V6.Lookup(addr)
}

// LookupInterface implements TableRegistry.
func (m *DefaultTableRegistry[V4, V6]) LookupInterface(table, ifname string) (string, bool) {
	value, ok := m.interfaces[table][ifname]
	return value, ok
}

// AddNetwork4 implements TableRegistry.
func (m *DefaultTableRegistry[V4, V6]) AddNetwork4(table string, network V4, value string) error {
	m.network(table).V4.Add(network, value)
	return nil
}

// AddNetwork6 implements TableRegistry.
func (m *DefaultTableRegistry[V4, V6]) AddNetwork6(table string, network V6, value string) error {
	m.network(table).V6.Add(network, value)
	return nil
}

// AddInterface implements TableRegistry, a later entry for the same name
// replacing the earlier one.
func (m *DefaultTableRegistry[V4, V6]) AddInterface(table, ifname, value string) error {
	interfaces, ok := m.interfaces[table]
	if !ok {
		interfaces = map[string]string{}
		m.interfaces[table] = interfaces
	}
	interfaces[ifname] = value
	return nil
}

// network returns the network table, created when missing.
func (m *DefaultTableRegistry[V4, V6]) network(table string) *networkTable[V4, V6] {
	networks, ok := m.networks[table]
	if !ok {
		networks = &networkTable[V4, V6]{}
		m.networks[table] = networks
	}
	return networks
}

// prefixTable holds the networks of one family grouped by their number of
// host bits, the most specific group first.
//
// A lookup scans the groups in that order, so the first network holding the
// address is the most specific one, and adding stays a search among at most
// as many groups as a family has bits.
type prefixTable[N Network] struct {
	groups []prefixGroup[N]
}

// prefixGroup holds the networks of one number of host bits in the order
// added.
type prefixGroup[N Network] struct {
	// HostBits is the number of host bits of every network of the group.
	HostBits int
	// Networks are the networks.
	Networks []N
	// Values are the values of the networks, by index.
	Values []string
}

// Lookup returns the value of the most specific network holding addr, the
// last added one among equally specific.
func (m *prefixTable[N]) Lookup(addr netip.Addr) (string, bool) {
	for _, group := range m.groups {
		if idx := lastHolding(group.Networks, addr); idx >= 0 {
			return group.Values[idx], true
		}
	}
	return "", false
}

// lastHolding returns the index of the last network holding addr, -1 when
// none does.
//
// The scan is a function of its own so that few values are live across the
// call to ContainsAddr, every one of them reloaded after it. The loop is
// slices.Backward written out, as a generic function does not inline the
// iterator, which cost a quarter of the scan.
func lastHolding[N Network](networks []N, addr netip.Addr) int {
	for idx := len(networks); idx > 0; {
		idx--
		if networks[idx].ContainsAddr(addr) {
			return idx
		}
	}
	return -1
}

// Add adds the network with its value to the group of its host bits.
func (m *prefixTable[N]) Add(network N, value string) {
	hostBits := network.NumHostBits()
	idx, found := slices.BinarySearchFunc(
		m.groups,
		hostBits,
		func(group prefixGroup[N], hostBits int) int {
			return cmp.Compare(group.HostBits, hostBits)
		},
	)
	if !found {
		m.groups = slices.Insert(m.groups, idx, prefixGroup[N]{HostBits: hostBits})
	}
	group := &m.groups[idx]
	group.Networks = append(group.Networks, network)
	group.Values = append(group.Values, value)
}
