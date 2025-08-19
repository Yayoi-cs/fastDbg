package main

import "golang.org/x/arch/x86/x86asm"

func Disassembly(code []byte, addr uint64) error {
	i := 0
	for i < len(code) {
		inst, err := x86asm.Decode(code[i:], 64)
		if err != nil {
			return err
		}
		Printf("0x%016x: %s\n", addr+uint64(i), x86asm.IntelSyntax(inst, addr+uint64(i), nil))

		i += inst.Len
	}

	return nil
}
