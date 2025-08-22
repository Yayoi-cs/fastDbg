package main

import (
	"golang.org/x/sys/unix"
)

func (dbger *TypeDbg) GetMemory(n uint, addr uintptr) ([]byte, error) {
	return doSyscall(dbger.rpc, func() ([]byte, error) {
		mem := make([]byte, n)
		count, err := unix.PtracePeekData(dbger.pid, addr, mem)
		if err != nil {
			return nil, err
		}
		if uint(count) != n {
			Printf("cannot read 0x%016x", uint64(addr)+uint64(count))
		}
		return mem, nil
	})
}

func (dbger *TypeDbg) SetMemory(data []byte, addr uintptr) error {
	_, err := doSyscall(dbger.rpc, func() (struct{}, error) {
		count, err := unix.PtracePokeData(dbger.pid, addr, data)
		if err != nil {
			return struct{}{}, err
		}
		if count != len(data) {
			Printf("cannot write 0x%016x", uint64(addr)+uint64(count))
		}
		return struct{}{}, nil
	})

	return err
}
