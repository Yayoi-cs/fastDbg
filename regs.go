package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"strings"
)

func (dbger *TypeDbg) GetRegs(regName string) (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}

	regName = strings.ToUpper(regName)

	switch regName {
	case "R15":
		return regs.R15, nil
	case "R14":
		return regs.R14, nil
	case "R13":
		return regs.R13, nil
	case "R12":
		return regs.R12, nil
	case "RBP":
		return regs.Rbp, nil
	case "RBX":
		return regs.Rbx, nil
	case "R11":
		return regs.R11, nil
	case "R10":
		return regs.R10, nil
	case "R9":
		return regs.R9, nil
	case "R8":
		return regs.R8, nil
	case "RAX":
		return regs.Rax, nil
	case "RCX":
		return regs.Rcx, nil
	case "RDX":
		return regs.Rdx, nil
	case "RSI":
		return regs.Rsi, nil
	case "RDI":
		return regs.Rdi, nil
	case "ORIG_RAX":
		return regs.Orig_rax, nil
	case "RIP":
		return regs.Rip, nil
	case "CS":
		return regs.Cs, nil
	case "EFLAGS":
		return regs.Eflags, nil
	case "RSP":
		return regs.Rsp, nil
	case "SS":
		return regs.Ss, nil
	case "FS_BASE":
		return regs.Fs_base, nil
	case "GS_BASE":
		return regs.Gs_base, nil
	case "DS":
		return regs.Ds, nil
	case "ES":
		return regs.Es, nil
	case "FS":
		return regs.Fs, nil
	case "GS":
		return regs.Gs, nil
	default:
		return 0, errors.New("invalid register")
	}
}

func (dbger *TypeDbg) getRegs() (*unix.PtraceRegs, error) {
	ptraceMutex.Lock()
	defer ptraceMutex.Unlock()
	regs := &unix.PtraceRegs{}
	err := unix.PtraceGetRegs(dbger.pid, regs)
	if err != nil {
		return nil, err
	}

	return regs, nil
}

func (dbger *TypeDbg) SetRegs(regName string, val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}

	regName = strings.ToUpper(regName)

	switch regName {
	case "R15":
		regs.R15 = val
	case "R14":
		regs.R14 = val
	case "R13":
		regs.R13 = val
	case "R12":
		regs.R12 = val
	case "RBP":
		regs.Rbp = val
	case "RBX":
		regs.Rbx = val
	case "R11":
		regs.R11 = val
	case "R10":
		regs.R10 = val
	case "R9":
		regs.R9 = val
	case "R8":
		regs.R8 = val
	case "RAX":
		regs.Rax = val
	case "RCX":
		regs.Rcx = val
	case "RDX":
		regs.Rdx = val
	case "RSI":
		regs.Rsi = val
	case "RDI":
		regs.Rdi = val
	case "ORIG_RAX":
		regs.Orig_rax = val
	case "RIP":
		regs.Rip = val
	case "CS":
		regs.Cs = val
	case "EFLAGS":
		regs.Eflags = val
	case "RSP":
		regs.Rsp = val
	case "SS":
		regs.Ss = val
	case "FS_BASE":
		regs.Fs_base = val
	case "GS_BASE":
		regs.Gs_base = val
	case "DS":
		regs.Ds = val
	case "ES":
		regs.Es = val
	case "FS":
		regs.Fs = val
	case "GS":
		regs.Gs = val
	default:
		return errors.New("invalid register")
	}
	err = dbger.setRegs(regs)

	return err
}

func (dbger *TypeDbg) setRegs(regs *unix.PtraceRegs) error {
	ptraceMutex.Lock()
	defer ptraceMutex.Unlock()
	pid := dbger.pid
	err := unix.PtraceSetRegs(pid, regs)
	if err != nil {
		return errors.New("PtraceSetRegs failed")
	}

	return nil
}

func (dbger *TypeDbg) GetR15() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.R15, nil
}

func (dbger *TypeDbg) GetR14() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.R14, nil
}

func (dbger *TypeDbg) GetR13() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.R13, nil
}

func (dbger *TypeDbg) GetR12() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.R12, nil
}

func (dbger *TypeDbg) GetRbp() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rbp, nil
}

func (dbger *TypeDbg) GetRbx() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rbx, nil
}

func (dbger *TypeDbg) GetR11() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.R11, nil
}

func (dbger *TypeDbg) GetR10() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.R10, nil
}

func (dbger *TypeDbg) GetR9() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.R9, nil
}

func (dbger *TypeDbg) GetR8() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.R8, nil
}

func (dbger *TypeDbg) GetRax() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rax, nil
}

func (dbger *TypeDbg) GetRcx() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rcx, nil
}

func (dbger *TypeDbg) GetRdx() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rdx, nil
}

func (dbger *TypeDbg) GetRsi() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rsi, nil
}

func (dbger *TypeDbg) GetRdi() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rdi, nil
}

func (dbger *TypeDbg) GetOrig_rax() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Orig_rax, nil
}

func (dbger *TypeDbg) GetRip() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rip, nil
}

func (dbger *TypeDbg) GetCs() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Cs, nil
}

func (dbger *TypeDbg) GetEflags() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Eflags, nil
}

func (dbger *TypeDbg) GetRsp() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rsp, nil
}

func (dbger *TypeDbg) GetSs() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Ss, nil
}

func (dbger *TypeDbg) GetFs_base() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Fs_base, nil
}

func (dbger *TypeDbg) GetGs_base() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Gs_base, nil
}

func (dbger *TypeDbg) GetDs() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Ds, nil
}

func (dbger *TypeDbg) GetEs() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Es, nil
}

func (dbger *TypeDbg) GetFs() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Fs, nil
}

func (dbger *TypeDbg) GetGs() (uint64, error) {
	regs, err := dbger.getRegs()
	if err != nil {
		return 0, err
	}
	return regs.Gs, nil
}

func (dbger *TypeDbg) SetR15(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.R15 = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetR14(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.R14 = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetR13(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.R13 = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetR12(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.R12 = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRbp(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rbp = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRbx(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rbx = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetR11(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.R11 = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetR10(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.R10 = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetR9(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.R9 = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetR8(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.R8 = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRax(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rax = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRcx(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rcx = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRdx(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rdx = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRsi(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rsi = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRdi(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rdi = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetOrig_rax(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Orig_rax = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRip(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rip = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetCs(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Cs = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetEflags(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Eflags = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetRsp(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Rsp = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetSs(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Ss = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetFs_base(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Fs_base = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetGs_base(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Gs_base = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetDs(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Ds = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetEs(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Es = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetFs(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Fs = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}

func (dbger *TypeDbg) SetGs(val uint64) error {
	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}
	regs.Gs = val
	err = dbger.setRegs(regs)
	if err != nil {
		return err
	}
	return nil
}
