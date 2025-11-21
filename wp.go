package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
)

const (
	USER_DR0_OFFSET = 848
	USER_DR1_OFFSET = 856
	USER_DR2_OFFSET = 864
	USER_DR3_OFFSET = 872
	USER_DR6_OFFSET = 880
	USER_DR7_OFFSET = 888
)

const (
	WP_EXEC      = 0b00
	WP_WRITE     = 0b01
	WP_IO        = 0b10
	WP_READWRITE = 0b11
)

const (
	WP_SIZE_1 = 0b00 // 1 byte
	WP_SIZE_2 = 0b01 // 2 bytes
	WP_SIZE_8 = 0b10 // 8 bytes
	WP_SIZE_4 = 0b11 // 4 bytes
)

type wpStruct struct {
	flg  bool
	addr uint64
}

var slotList [4]wpStruct

func findEmpty() uint64 {
	for i, s := range slotList {
		if s.flg == false {
			return uint64(i)
		}
	}
	return uint64(-1)
}

func (dbger *TypeDbg) SetWatchpoint(wpAddr uint64, wpSize uint64, wpCondition uint64) error {
	slot := findEmpty()
	if slot == uint64(-1) {
		return fmt.Errorf("reached to maximum number of watch point")
	}
	slotList[slot] = wpStruct{
		flg:  true,
		addr: wpAddr,
	}

	buf := make([]byte, 8)
	err := doSyscallErr(dbger.rpc, func() error {
		_, err := unix.PtracePeekUser(dbger.pid, USER_DR7_OFFSET, buf)
		return err
	})
	if err != nil {
		return fmt.Errorf("PtracePeekUser failed")
	}

	dr7 := binary.LittleEndian.Uint64(buf)
	drOffset := uintptr(USER_DR0_OFFSET + slot*8)
	putBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(putBuf, wpAddr)
	err = doSyscallErr(dbger.rpc, func() error {
		_, err := unix.PtracePokeUser(dbger.pid, drOffset, putBuf)
		return err
	})
	if err != nil {
		return fmt.Errorf("PtracePokeUser failed")
	}
	var enableBit uint64 = 1 << (slot * 2) // Set local enable bit for DR0-DR3 at position 0, 2, 4, or 6
	var cShift uint64 = 16 + (slot * 4)
	var cBits uint64 = wpCondition << cShift
	var sShift uint64 = 18 + (slot * 4)
	var sizeBits uint64 = wpSize << sShift

	clearMask := ^(uint64(0xF<<cShift) | uint64(3<<(slot*2)))
	newDR7 := (dr7 & clearMask) | enableBit | cBits | sizeBits

	drBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(drBuf, newDR7)
	err = doSyscallErr(dbger.rpc, func() error {
		_, err := unix.PtracePokeUser(dbger.pid, USER_DR7_OFFSET, drBuf)
		return err
	})

	return err
}

func (dbger *TypeDbg) clearWatchpoint(slot uint64) error {
	if slot > uint64(len(slotList)) {
		for i, s := range slotList {
			if s.addr == slot {
				slot = uint64(i)
				break
			}
		}
	}
	dr0Off := uintptr(USER_DR0_OFFSET + slot*8)
	putBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(putBuf, 0)
	err := doSyscallErr(dbger.rpc, func() error {
		_, err := unix.PtracePokeUser(dbger.pid, dr0Off, putBuf)
		return err
	})
	if err != nil {
		return fmt.Errorf("PtracePokeUser failed")
	}
	buf := make([]byte, 8)
	err = doSyscallErr(dbger.rpc, func() error {
		_, err := unix.PtracePeekUser(dbger.pid, USER_DR7_OFFSET, buf)
		return err
	})
	if err != nil {
		return fmt.Errorf("PtracePeekUser failed")
	}

	dr7 := binary.LittleEndian.Uint64(buf)

	clearMask := ^uint64(3 << (slot * 2))
	newDR7 := dr7 & clearMask

	drBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(drBuf, newDR7)
	err = doSyscallErr(dbger.rpc, func() error {
		_, err := unix.PtracePokeUser(dbger.pid, USER_DR7_OFFSET, drBuf)
		return err
	})

	return err
}
