package vm

import "net/netip"

// Tables is the default TableRegistry: the networks of a table are scanned
// in the order added, the interfaces looked up by exact name.
type Tables[V4, V6 Network] struct {
	networks   map[string]*networkTable[V4, V6]
	interfaces map[string]map[string]string
}

// networkTable holds the networks of one table by family.
type networkTable[V4, V6 Network] struct {
	// V4 are the IPv4 networks in the order added.
	V4 []V4
	// V6 are the IPv6 networks in the order added.
	V6 []V6
}

// NewTables returns an empty registry.
func NewTables[V4, V6 Network]() *Tables[V4, V6] {
	return &Tables[V4, V6]{
		networks:   map[string]*networkTable[V4, V6]{},
		interfaces: map[string]map[string]string{},
	}
}

// LookupNetwork implements TableRegistry.
func (m *Tables[V4, V6]) LookupNetwork(table string, addr netip.Addr) bool {
	networks, ok := m.networks[table]
	if !ok {
		return false
	}
	if addr.Is4() {
		for _, network := range networks.V4 {
			if network.ContainsAddr(addr) {
				return true
			}
		}
		return false
	}
	for _, network := range networks.V6 {
		if network.ContainsAddr(addr) {
			return true
		}
	}
	return false
}

// LookupInterface implements TableRegistry.
func (m *Tables[V4, V6]) LookupInterface(table, ifname string) (string, bool) {
	value, ok := m.interfaces[table][ifname]
	return value, ok
}

// AddNetwork4 implements TableRegistry.
func (m *Tables[V4, V6]) AddNetwork4(table string, network V4) {
	networks := m.network(table)
	networks.V4 = append(networks.V4, network)
}

// AddNetwork6 implements TableRegistry.
func (m *Tables[V4, V6]) AddNetwork6(table string, network V6) {
	networks := m.network(table)
	networks.V6 = append(networks.V6, network)
}

// AddInterface implements TableRegistry, a later entry for the same name
// replacing the earlier one.
func (m *Tables[V4, V6]) AddInterface(table, ifname, value string) {
	interfaces, ok := m.interfaces[table]
	if !ok {
		interfaces = map[string]string{}
		m.interfaces[table] = interfaces
	}
	interfaces[ifname] = value
}

// network returns the network table, created when missing.
func (m *Tables[V4, V6]) network(table string) *networkTable[V4, V6] {
	networks, ok := m.networks[table]
	if !ok {
		networks = &networkTable[V4, V6]{}
		m.networks[table] = networks
	}
	return networks
}
