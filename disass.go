package main

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

/*

#cgo pkg-config: capstone
#include <capstone/capstone.h>

char* get_mnemonic(cs_insn* insn) { return insn->mnemonic; }
char* get_op_str(cs_insn* insn) { return insn->op_str; }
uint64_t get_address(cs_insn* insn) { return insn->address; }
uint16_t get_size(cs_insn* insn) { return insn->size; }
*/
import "C"

// disass prints `n` instructions starting at addr. n is a count of
// instructions (lines), not a byte size. Use disass2ret to walk until a
// `ret` instruction.
func (dbger *TypeDbg) disass(addr uint64, n uint) {
	if n == 0 {
		n = 16
	}

	// x86_64 instructions are at most 15 bytes; over-read so capstone has
	// enough material to satisfy `n` even for large encodings. Cap to keep
	// the request bounded.
	bytesNeeded := n * 15
	if bytesNeeded > 4096 {
		bytesNeeded = 4096
	}

	code, ok := func() ([]byte, bool) {
		for _, b := range Bps {
			if uint64(b.addr) == addr && b.isEnable {
				buf, err := dbger.GetMemory(bytesNeeded, uintptr(addr))
				if err != nil {
					return nil, false
				}
				copy(buf, b.instr)
				return buf, true
			}
		}
		return nil, false
	}()

	var err error
	if !ok {
		code, err = dbger.GetMemory(bytesNeeded, uintptr(addr))
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

	count := C.cs_disasm(handle, (*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)), C.uint64_t(addr), C.size_t(n), &insn)
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
			v, err := strconv.ParseUint(op_str_go, 0, 64)
			if err != nil {
				fmt.Printf("%s0x%016x%s: %s%s %s%s\n", ColorBlue, C.get_address(inst), ColorReset, ColorPurple, mnemonic_str, op_str_go, ColorReset)
			} else {
				fmt.Printf("%s0x%016x%s: %s%s %s%s%s\n", ColorBlue, C.get_address(inst), ColorReset, ColorPurple, mnemonic_str, op_str_go, dbger.addr2some(v), ColorReset)
			}
		} else {
			fmt.Printf("%s0x%016x%s: %s%s%s\n", ColorBlue, C.get_address(inst), ColorReset, ColorPurple, mnemonic_str, ColorReset)
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
			v, err := strconv.ParseUint(op_str_go, 0, 64)
			if err != nil {
				ret_str = fmt.Sprintf("%s %s", ret_str, op_str_go)
			} else {
				ret_str = fmt.Sprintf("%s %s%s", ret_str, op_str_go, dbger.addr2some(v))
			}
		}
	}

	return &ret_str, nil
}

func (dbger *TypeDbg) disass2ret(addr uint64) {
	currentAddr := addr
	// Safety cap so a function without a reachable `ret` (e.g. tail-calls
	// only, padding/zeroes, or corrupted memory) doesn't loop forever.
	const maxInstructions = 4096
	steps := 0

	for {
		if steps >= maxInstructions {
			Printf("disass: stopped after %d instructions (no ret found)\n", maxInstructions)
			return
		}
		steps++
		code, ok := func() ([]byte, bool) {
			for _, b := range Bps {
				if uint64(b.addr) == currentAddr && b.isEnable {
					code, err := dbger.GetMemory(16, uintptr(currentAddr))
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
			code, err = dbger.GetMemory(16, uintptr(currentAddr))
			if err != nil {
				Printf("Error reading memory at 0x%016x: %v\n", currentAddr, err)
				return
			}
		}

		var handle C.csh
		var insn *C.cs_insn
		ret := C.cs_open(C.CS_ARCH_X86, C.CS_MODE_64, &handle)
		if ret != C.CS_ERR_OK {
			Printf("Failed to open capstone engine: %d\n", ret)
			return
		}

		count := C.cs_disasm(handle, (*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)), C.uint64_t(currentAddr), 1, &insn)
		if count == 0 {
			Printf("Failed to disassemble instruction at address 0x%016x\n", currentAddr)
			C.cs_close(&handle)
			return
		}

		instructions := (*[1000]C.cs_insn)(unsafe.Pointer(insn))[:count]
		inst := &instructions[0]

		mnemonic := C.get_mnemonic(inst)
		op_str := C.get_op_str(inst)

		if mnemonic == nil {
			Printf("0x%016x: <invalid mnemonic>\n", C.get_address(inst))
			C.cs_free(insn, count)
			C.cs_close(&handle)
			return
		}

		mnemonic_str := C.GoString(mnemonic)
		op_str_go := ""
		if op_str != nil {
			op_str_go = C.GoString(op_str)
		}

		if op_str_go != "" {
			v, err := strconv.ParseUint(op_str_go, 0, 64)
			if err != nil {
				fmt.Printf("%s0x%016x%s: %s%s %s%s\n", ColorBlue, C.get_address(inst), ColorReset, ColorPurple, mnemonic_str, op_str_go, ColorReset)
			} else {
				fmt.Printf("%s0x%016x%s: %s%s %s%s%s\n", ColorBlue, C.get_address(inst), ColorReset, ColorPurple, mnemonic_str, op_str_go, dbger.addr2some(v), ColorReset)
			}
		} else {
			fmt.Printf("%s0x%016x%s: %s%s%s\n", ColorBlue, C.get_address(inst), ColorReset, ColorPurple, mnemonic_str, ColorReset)
		}

		isRet := strings.HasPrefix(mnemonic_str, "ret")

		instSize := uint64(C.get_size(inst))

		C.cs_free(insn, count)
		C.cs_close(&handle)
		if isRet {
			break
		}

		currentAddr += instSize

		if instSize == 0 {
			Printf("Warning: instruction at 0x%016x has size 0, stopping disassembly\n", currentAddr-instSize)
			break
		}
	}
}
