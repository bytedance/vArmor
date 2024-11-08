package tracer

type BpfProcessEvent struct {
	Type       uint32
	ParentPid  uint32
	ParentTgid uint32
	ChildPid   uint32
	ChildTgid  uint32
	MntNsId    uint32
	ParentTask [16]uint8
	ChildTask  [16]uint8
	Filename   [64]uint8
}
