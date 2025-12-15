package main

type Debugger interface {
	GetMemory(size uint, addr uintptr) ([]byte, error)
	SetMemory(data []byte, addr uintptr) error
	GetRip() (uint64, error)
	SetRip(rip uint64) error
	Continue() error
	Step() error
	SetBreakpoint(addr uintptr) error
	RemoveBreakpoint(addr uintptr) error
	ResolveAddrToSymbol(addr uint64) (*Symbol, uint64, error)
	GetProcMaps() []*proc
	DisassOne(addr uintptr) (*string, error)
	IsActive() bool
}
