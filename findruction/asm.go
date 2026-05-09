// Package findruction integrates the findruction2 instruction-finder
// algorithm into fastDbg. Given an assembly string, it assembles it into
// machine code and then scans every executable region of either the loaded
// ELF files (default mode, parallel) or live process memory (when the user
// provides an address range) for byte matches.
package findruction

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
)

// AsmToBytes assembles an x86_64 Intel-syntax assembly snippet into raw
// machine code. Internally it shells out to GNU `as` (binutils) and reads
// the resulting `.text` section. We use `as` rather than a Go-native
// assembler because keystone has no maintained pure-Go binding and the
// alternative — bundling a CGo dependency — adds more friction than a
// one-shot subprocess for a command users invoke interactively.
//
// `asm` may contain multiple instructions separated by `;` or newlines.
// Examples:
//
//	"swapgs"
//	"swapgs; ret"
//	"mov rax, 0x60; syscall"
func AsmToBytes(asm string) ([]byte, error) {
	src, err := os.CreateTemp("", "findruction_*.s")
	if err != nil {
		return nil, err
	}
	defer os.Remove(src.Name())
	objPath := src.Name() + ".o"
	defer os.Remove(objPath)

	prog := ".intel_syntax noprefix\n.text\n" + asm + "\n"
	if _, err := src.WriteString(prog); err != nil {
		src.Close()
		return nil, err
	}
	src.Close()

	cmd := exec.Command("as", "--64", "-o", objPath, src.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("as failed: %s: %v", string(out), err)
	}

	obj, err := elf.Open(objPath)
	if err != nil {
		return nil, err
	}
	defer obj.Close()

	text := obj.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("assembled object has no .text section")
	}
	data, err := text.Data()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("assembled .text is empty")
	}
	return data, nil
}
