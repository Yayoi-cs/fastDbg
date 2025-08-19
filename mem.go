package main

import (
	"errors"
	"golang.org/x/sys/unix"
)

func (dbger *TypeDbg) GetMemory(n uint, addr uintptr) ([]byte, error) {
	mem := make([]byte, n)
	count, err := unix.PtracePeekData(dbger.pid, addr, mem)
	if err != nil {
		return nil, err
	}
	if uint(count) != n {
		return nil, errors.New("PtracePeekData failed")
	}
	return mem, nil
}

func (dbger *TypeDbg) SetMemory(data []byte, addr uintptr) error {
	count, err := unix.PtracePokeData(dbger.pid, addr, data)
	if err != nil {
		return err
	}
	if count != len(data) {
		return errors.New("PtracePokeData failed")
	}
	return nil
}
