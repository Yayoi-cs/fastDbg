package main

import (
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
)

type TypeBp struct {
	pid      int
	addr     uintptr
	instr    []byte
	isEnable bool
}

var Bps []TypeBp

func NewBp(bpAddr uintptr, pid int) (*TypeBp, error) {
	bp := &TypeBp{
		pid:   pid,
		addr:  bpAddr,
		instr: make([]byte, 8),
	}
	if err := bp.enableBp(); err != nil {
		return nil, err
	}
	Bps = append(Bps, *bp)
	Printf("breakpoint %d added at %x\n", len(Bps)-1, bpAddr)
	return bp, nil
}

func EnableBp(idx int) error {
	if len(Bps) <= idx {
		return errors.New("invalid index")
	}
	if Bps[idx].isEnable {
		return errors.New("already enabled")
	}
	err := Bps[idx].enableBp()
	if err != nil {
		return err
	}
	Printf("breakpoint %d enabled at %x\n", idx, Bps[idx].addr)
	return nil
}

func DisableBp(idx int) error {
	if len(Bps) <= idx {
		return errors.New("invalid index")
	}
	if !Bps[idx].isEnable {
		return errors.New("already disabled")
	}
	err := Bps[idx].disableBp()
	if err != nil {
		return err
	}
	Printf("breakpoint %d disabled at %x\n", idx, Bps[idx].addr)
	return nil
}

func (bp *TypeBp) enableBp() error {
	ptraceMutex.Lock()
	defer ptraceMutex.Unlock()
	_, err := unix.PtracePeekData(bp.pid, bp.addr, bp.instr)
	if err != nil {
		return err
	}
	origInstr := binary.LittleEndian.Uint64(bp.instr)
	int3Instr := (origInstr & ^uint64(0xff)) | 0xcc
	int3InstrLittle := make([]byte, 8)
	binary.LittleEndian.PutUint64(int3InstrLittle, int3Instr)
	_, err = unix.PtracePokeData(bp.pid, bp.addr, int3InstrLittle)
	if err != nil {
		return err
	}
	bp.isEnable = true
	return nil
}

func (bp *TypeBp) disableBp() error {
	ptraceMutex.Lock()
	defer ptraceMutex.Unlock()
	int3InstrLittle := make([]byte, 8)
	_, err := unix.PtracePeekData(bp.pid, bp.addr, int3InstrLittle)
	if err != nil {
		return err
	}
	int3Instr := binary.LittleEndian.Uint64(int3InstrLittle)
	origInstr := binary.LittleEndian.Uint64(bp.instr)
	newInstr := (int3Instr & ^uint64(0xff)) | (origInstr & 0xff)
	binInstr := make([]byte, 8)
	binary.LittleEndian.PutUint64(binInstr, newInstr)
	_, err = unix.PtracePokeData(bp.pid, bp.addr, binInstr)
	if err != nil {
		return err
	}
	bp.isEnable = false
	return nil
}
