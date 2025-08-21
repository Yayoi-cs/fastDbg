package main

import (
	"golang.org/x/sys/unix"
)

func (dbger *TypeDbg) GetMemory(n uint, addr uintptr) ([]byte, error) {
	ptraceMutex.Lock()
	defer ptraceMutex.Unlock()
	mem := make([]byte, n)
	count, err := unix.PtracePeekData(dbger.pid, addr, mem)
	if err != nil {
		return nil, err
	}
	if uint(count) != n {
		Printf("cannot read 0x%016x", uint64(addr)+uint64(count))
	}
	return mem, nil
}

func (dbger *TypeDbg) SetMemory(data []byte, addr uintptr) error {
	ptraceMutex.Lock()
	defer ptraceMutex.Unlock()
	count, err := unix.PtracePokeData(dbger.pid, addr, data)
	if err != nil {
		return err
	}
	if count != len(data) {
		Printf("cannot write 0x%016x", uint64(addr)+uint64(count))
	}
	return nil
}
