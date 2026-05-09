// Package common holds debugger primitives that are independent of whether
// we're attached to a userland process via ptrace or to a guest via the QEMU
// GDB stub. Functions here only depend on the Reader interface (a single
// GetMemory method), so both *main.TypeDbg and *qemu.QemuDbg satisfy it
// without modification.
package common

// Reader is the minimal contract a debugger backend must satisfy for the
// common helpers (hex dump, search, etc.) to work against it.
type Reader interface {
	GetMemory(size uint, addr uintptr) ([]byte, error)
}
