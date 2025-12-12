package qemu

import (
	"fmt"
	"unsafe"
)

/*

#cgo pkg-config: capstone
#include <capstone/capstone.h>

static inline char* qemu_get_mnemonic(cs_insn* insn) { return insn->mnemonic; }
static inline char* qemu_get_op_str(cs_insn* insn) { return insn->op_str; }
static inline uint64_t qemu_get_address(cs_insn* insn) { return insn->address; }
static inline uint16_t qemu_get_size(cs_insn* insn) { return insn->size; }
*/
import "C"

func (q *QemuDbg) disass(addr uint64, sz uint) error {
	code, err := q.GetMemory(sz, uintptr(addr))
	if err != nil {
		fmt.Printf("Error reading memory at 0x%016x: %v\n", addr, err)
		return err
	}

	var handle C.csh
	var insn *C.cs_insn
	ret := C.cs_open(C.CS_ARCH_X86, C.CS_MODE_64, &handle)
	if ret != C.CS_ERR_OK {
		return fmt.Errorf("capstone open failed")
	}

	defer C.cs_close(&handle)

	count := C.cs_disasm(handle, (*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)), C.uint64_t(addr), 0, &insn)
	if count == 0 {
		return fmt.Errorf("disassembly failed")
	}

	defer C.cs_free(insn, count)

	instructions := (*[1000]C.cs_insn)(unsafe.Pointer(insn))[:count]
	for i := 0; i < int(count); i++ {
		inst := &instructions[i]
		mnemonic := C.qemu_get_mnemonic(inst)
		op_str := C.qemu_get_op_str(inst)

		if mnemonic == nil {
			fmt.Printf("0x%016x: <invalid mnemonic>\n", C.qemu_get_address(inst))
			continue
		}

		mnemonic_str := C.GoString(mnemonic)
		op_str_go := ""
		if op_str != nil {
			op_str_go = C.GoString(op_str)
		}

		if op_str_go != "" {
			fmt.Printf("%s0x%016x%s: %s%s %s%s\n",
				ColorBlue, C.qemu_get_address(inst), ColorReset,
				ColorPurple, mnemonic_str, op_str_go, ColorReset)
		} else {
			fmt.Printf("%s0x%016x%s: %s%s%s\n",
				ColorBlue, C.qemu_get_address(inst), ColorReset,
				ColorPurple, mnemonic_str, ColorReset)
		}
	}

	return nil
}
