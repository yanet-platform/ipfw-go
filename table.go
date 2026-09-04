package ipfw

// TableKind is a table command.
type TableKind uint8

// The table commands.
const (
	_ TableKind = iota
	TableCreate
	TableAdd
)

// TableType is the `type` of a created table, TableTypeUnset when omitted.
type TableType uint8

// The table types.
const (
	TableTypeUnset TableType = iota
	TableTypeAddr
	TableTypeIface
	TableTypeNumber
	TableTypeFlow
	TableTypeMAC
)

// TableKeyKind classifies the key of a table entry by its shape, the type of
// the table telling what a name stands for.
type TableKeyKind uint8

// The table key kinds.
const (
	_ TableKeyKind = iota
	TableKeyNetwork4
	TableKeyNetwork6
	// TableKeyHostname is a name of hostname shape, letters and digits
	// around a dot, which an interface table takes as an interface name.
	TableKeyHostname
	// TableKeyName is any other key, an interface name, a macro or a
	// hostname with a prefix length among them.
	TableKeyName
)

// TableKey is the key of a table entry, unvalidated text never cut short.
type TableKey struct {
	// Kind is the shape the key was classified as.
	Kind TableKeyKind
	// Text is the raw key.
	Text string
}

// Table is a `table NAME create|add …` command.
type Table struct {
	// Name is the table name.
	Name string
	// Kind is the command.
	Kind TableKind
	// Type is set by create.
	Type TableType
	// Key is set by add.
	Key TableKey
	// Value is the optional value of an add.
	Value string
}
