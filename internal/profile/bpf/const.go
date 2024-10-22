package bpf

const (
	// BPF enforcer running mode.
	EnforceMode  = 0x00000001
	AuditMode    = 0x00000002
	ComplainMode = 0x00000004

	// Matching Flags
	PreciseMatch = 0x00000001
	GreedyMatch  = 0x00000002
	PrefixMatch  = 0x00000004
	SuffixMatch  = 0x00000008
	CidrMatch    = 0x00000020
	Ipv4Match    = 0x00000040
	Ipv6Match    = 0x00000080
	PortMatch    = 0x00000100

	// Matching Permissions
	AaMayExec     = 0x00000001
	AaMayWrite    = 0x00000002
	AaMayRead     = 0x00000004
	AaMayAppend   = 0x00000008
	AaPtraceTrace = 0x00000002
	AaPtraceRead  = 0x00000004
	AaMayBeTraced = 0x00000008
	AaMayBeRead   = 0x00000010
	AaMayUmount   = 0x00000200
)
