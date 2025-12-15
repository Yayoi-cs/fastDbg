package qemu

import (
	"fmt"
	"strings"
)

type QemuSymbolResolver struct {
	dbg *QemuDbg
}

func NewQemuSymbolResolver(dbg *QemuDbg) *QemuSymbolResolver {
	return &QemuSymbolResolver{dbg: dbg}
}

func (r *QemuSymbolResolver) ResolveRegister(name string) (uint64, error) {
	regs, err := r.dbg.GetRegs()
	if err != nil {
		return 0, fmt.Errorf("failed to get registers: %v", err)
	}

	switch strings.ToLower(name) {
	case "rax":
		return regs.Rax, nil
	case "rbx":
		return regs.Rbx, nil
	case "rcx":
		return regs.Rcx, nil
	case "rdx":
		return regs.Rdx, nil
	case "rsi":
		return regs.Rsi, nil
	case "rdi":
		return regs.Rdi, nil
	case "rbp":
		return regs.Rbp, nil
	case "rsp":
		return regs.Rsp, nil
	case "r8":
		return regs.R8, nil
	case "r9":
		return regs.R9, nil
	case "r10":
		return regs.R10, nil
	case "r11":
		return regs.R11, nil
	case "r12":
		return regs.R12, nil
	case "r13":
		return regs.R13, nil
	case "r14":
		return regs.R14, nil
	case "r15":
		return regs.R15, nil
	case "rip":
		return regs.Rip, nil
	case "eflags":
		return regs.Eflags, nil
	case "cs":
		return uint64(regs.Cs), nil
	case "ss":
		return uint64(regs.Ss), nil
	case "ds":
		return uint64(regs.Ds), nil
	case "es":
		return uint64(regs.Es), nil
	case "fs":
		return uint64(regs.Fs), nil
	case "gs":
		return uint64(regs.Gs), nil
	default:
		return 0, fmt.Errorf("unknown register: %s", name)
	}
}

func (r *QemuSymbolResolver) ResolveSymbol(name string) (uint64, error) {
	return 0, fmt.Errorf("symbol resolution not available for QEMU remote debugging")
}
