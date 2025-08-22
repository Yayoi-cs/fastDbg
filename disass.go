package main

import (
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

func disass(code []byte, addr uint64) {
	var handle C.csh
	var insn *C.cs_insn

	C.cs_open(C.CS_ARCH_X86, C.CS_MODE_64, &handle)
	count := C.cs_disasm(handle, (*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)), C.uint64_t(addr), 0, &insn)

	instructions := (*[1000]C.cs_insn)(unsafe.Pointer(insn))[:count]
	for i := 0; i < int(count); i++ {
		inst := &instructions[i]
		Printf("0x%016x: %s %s\n",
			C.get_address(inst),
			C.GoString(C.get_mnemonic(inst)),
			C.GoString(C.get_op_str(inst)))
	}

	C.cs_free(insn, count)
	C.cs_close(&handle)
}
