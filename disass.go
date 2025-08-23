package main

import (
	"fmt"
	"unsafe"
)

/*

#cgo pkg-config: capstone
#include <capstone/capstone.h>

char* get_mnemonic(cs_insn* insn) { return insn->mnemonic; }
char* get_op_str(cs_insn* insn) { return insn->op_str; }
uint64_t get_address(cs_insn* insn) { return insn->address; }
*/
import "C"

func (dbger *TypeDbg) disass(addr uint64, sz uint) {
	code, ok := func() ([]byte, bool) {
		for _, b := range Bps {
			if uint64(b.addr) == addr && b.isEnable {
				code, _ := dbger.GetMemory(sz, uintptr(addr))
				copy(code, b.instr)
				return code, true
			}
		}
		return nil, false
	}()

	var err error = nil
	if !ok {
		code, err = dbger.GetMemory(32, uintptr(addr))
	}

	if err != nil {
		Printf("Error reading memory at 0x%016x: %v\n", addr, err)
		return
	}

	var handle C.csh
	var insn *C.cs_insn
	ret := C.cs_open(C.CS_ARCH_X86, C.CS_MODE_64, &handle)
	if ret != C.CS_ERR_OK {
		Printf("Failed to open capstone engine: %d\n", ret)
		return
	}

	defer C.cs_close(&handle)

	count := C.cs_disasm(handle, (*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)), C.uint64_t(addr), 0, &insn)
	if count == 0 {
		Printf("Failed to disassemble instruction at address 0x%016x\n", addr)
		return
	}

	defer C.cs_free(insn, count)

	instructions := (*[1000]C.cs_insn)(unsafe.Pointer(insn))[:count]
	for i := 0; i < int(count); i++ {
		inst := &instructions[i]
		mnemonic := C.get_mnemonic(inst)
		op_str := C.get_op_str(inst)

		if mnemonic == nil {
			Printf("0x%016x: <invalid mnemonic>\n", C.get_address(inst))
			continue
		}

		mnemonic_str := C.GoString(mnemonic)
		op_str_go := ""
		if op_str != nil {
			op_str_go = C.GoString(op_str)
		}

		if op_str_go != "" {
			Printf("0x%016x: %s %s\n", C.get_address(inst), mnemonic_str, op_str_go)
		} else {
			Printf("0x%016x: %s\n", C.get_address(inst), mnemonic_str)
		}
	}
}

func (dbger *TypeDbg) disassOne(addr uintptr) (*string, error) {
	code, ok := func() ([]byte, bool) {
		for _, b := range Bps {
			if uint64(b.addr) == uint64(addr) && b.isEnable {
				code, err := dbger.GetMemory(8, addr)
				if err != nil {
					return nil, false
				}
				if len(b.instr) > 0 {
					copy(code, b.instr)
				}
				return code, true
			}
		}
		return nil, false
	}()

	var err error
	if !ok {
		code, err = dbger.GetMemory(8, addr)
		if err != nil {
			return nil, err
		}
	}

	var handle C.csh
	var insn *C.cs_insn

	ret := C.cs_open(C.CS_ARCH_X86, C.CS_MODE_64, &handle)
	if ret != C.CS_ERR_OK {
		return nil, fmt.Errorf("failed to open capstone engine: %d", ret)
	}

	defer C.cs_close(&handle)

	count := C.cs_disasm(handle, (*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)), C.uint64_t(addr), 0, &insn)

	if count == 0 {
		return nil, fmt.Errorf("failed to disassemble instruction at address 0x%x", addr)
	}

	defer C.cs_free(insn, count)

	instructions := (*[1000]C.cs_insn)(unsafe.Pointer(insn))[:count]
	if len(instructions) == 0 {
		return nil, fmt.Errorf("no instructions disassembled")
	}

	inst := &instructions[0]
	mnemonic := C.get_mnemonic(inst)
	op_str := C.get_op_str(inst)

	if mnemonic == nil {
		return nil, fmt.Errorf("failed to get mnemonic")
	}

	ret_str := C.GoString(mnemonic)
	if op_str != nil {
		op_str_go := C.GoString(op_str)
		if op_str_go != "" {
			ret_str = fmt.Sprintf("%s %s", ret_str, op_str_go)
		}
	}

	return &ret_str, nil
}
