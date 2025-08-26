package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var cmd = map[string]func(*TypeDbg, interface{}) error{
	`^\s*(b|break|B|BREAK)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`:                                          (*TypeDbg).cmdBreak,
	`^\s*(b|break|B|BREAK)\s+(pie|PIE)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`:                              (*TypeDbg).cmdBreakPie,
	`^\s*(enable)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`:                                                   (*TypeDbg).cmdEnable,
	`^\s*(disable)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`:                                                  (*TypeDbg).cmdDisable,
	`^\s*(disass)(\s+(0[xx][0-9a-fa-f]+|0[0-7]+|[1-9][0-9]*|0))?(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`: (*TypeDbg).cmdDisass,
	`^\s*(r|run|R|RUN)(?:\s+(.+))?$`:                                                                              (*TypeDbg).cmdRun,
	`^\s*(s|start|S|START)(?:\s+(.+))?$`:                                                                          (*TypeDbg).cmdStart,
	`^\s*(regs)(?:\s+(.+))?$`:                                                                                     (*TypeDbg).cmdRegs,
	`^\s*(!)(.+)$`:                                                                                                (*TypeDbg).cmdCmd,
	`^\s*(c|continue|cont|C|CONTINUE|CONT)\s*$`:                                                                   (*TypeDbg).cmdContinue,
	`^\s*(step|STEP)\s*$`:                                                                                         (*TypeDbg).cmdStep,
	`^\s*(context|CONTEXT)\s*$`:                                                                                   (*TypeDbg).cmdContext,
	`^\s*(stack|stk|STACK|STK)(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`:                                   (*TypeDbg).cmdStack,
	`^\s*(vmmap|VMMAP)(\s+\w+)*\s*$`:                                                                              (*TypeDbg).cmdVmmap,
	`^\s*(sym|symbol|SYM|SYMBOL)(\s+\w+)*\s*$`:                                                                    (*TypeDbg).cmdSym,
	`^\s*(got|GOT)\s*$`:                                                                                           (*TypeDbg).cmdGot,
	`^\s*(vis|visual-heap|VIS|VISUAL-HEAP)\s*$`:                                                                   (*TypeDbg).cmdVisualHeap,
	`^\s*(db|xxd)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`:                      (*TypeDbg).cmdDumpByte,
	`^\s*(dd|xxd\s+dword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`:              (*TypeDbg).cmdDumpDword,
	`^\s*(dq|xxd\s+qword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`:              (*TypeDbg).cmdDumpQword,
	`^\s*(tel|telescope|TEL|TELESCOPE)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`: (*TypeDbg).cmdTelescope,
}

func (dbger *TypeDbg) cmdExec(req string) error {
	for rgx, fnc := range cmd {
		regex, err := regexp.Compile(rgx)
		if err != nil {
			return err
		}

		if regex.MatchString(req) {
			m := regex.FindStringSubmatch(req)
			err = fnc(dbger, m)
			return err
		}
	}
	return errors.New("unknown command")
}

var tmpBps []uintptr
var tmpPieBps []uintptr

func (dbger *TypeDbg) cmdBreak(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	if !dbger.isStart {
		tmpBps = append(tmpBps, uintptr(addr))
		Printf("booked breakpoint %d @ %x\n", len(tmpBps), addr)
		return nil
	}

	_, err = dbger.NewBp(uintptr(addr), dbger.pid)

	return err
}

func (dbger *TypeDbg) cmdBreakPie(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[3], 0, 64)
	if err != nil {
		return err
	}

	addr = addr + libRoots[0].base

	if !dbger.isStart {
		tmpPieBps = append(tmpPieBps, uintptr(addr))
		Printf("booked breakpoint %d @ %x\n", len(tmpPieBps), addr)
		return nil
	}

	_, err = dbger.NewBp(uintptr(addr), dbger.pid)

	return err
}

func (dbger *TypeDbg) cmdEnable(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	off, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	err = dbger.EnableBp(int(off))
	return err
}

func (dbger *TypeDbg) cmdDisable(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	off, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	err = dbger.DisableBp(int(off))
	return err
}

func (dbger *TypeDbg) cmdRun(a interface{}) error {
	err := dbger.cmdStart(a)
	if err != nil {
		return err
	}

	err = dbger.Continue()
	if err != nil {
		return err
	}

	ws, err := dbger.wait()
	if err != nil {
		return err
	}
	if !ws.Exited() {
		cls()
		dbger.cmdContext(nil)
	}

	return nil
}

func (dbger *TypeDbg) cmdStart(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	tmpDbger, err := Run(dbger.path, args[2:]...)
	if err != nil {
		return err
	}
	mainDbger = *tmpDbger

	dbger.Reload()

	for _, addr := range tmpBps {
		_, err = dbger.NewBp(addr, dbger.pid)
		if err != nil {
			return err
		}
	}

	for _, addr := range tmpPieBps {
		_, err = dbger.NewBp(addr+uintptr(libRoots[0].base), dbger.pid)
		if err != nil {
			return err
		}
	}

	if a != nil {
		cls()
		dbger.cmdContext(nil)
	}

	resolvedN = 0
	return nil
}

func (dbger *TypeDbg) cmdContinue(a interface{}) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}

	err := dbger.Continue()
	if err != nil {
		return err
	}

	ws, err := dbger.wait()
	if err != nil {
		return err
	}

	if !ws.Exited() {
		cls()
		dbger.cmdContext(nil)
	}

	return err
}

func (dbger *TypeDbg) cmdContext(a interface{}) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}
	dbger.Reload()

	hLine("registers")

	if !dbger.isProcessAlive() {
		return errors.New("process is not alive")
	}

	var regs *unix.PtraceRegs
	var err error

	regs, err = dbger.getRegs()
	if err != nil {
		return err
	}

	if regs == nil {
		return errors.New("nil registers")
	}

	rip, err := dbger.GetRip()
	if err != nil {
		return err
	}

	Printf("$rax   : 0x%016x%s\n", regs.Rax, dbger.addr2some(regs.Rax))
	Printf("$rbx   : 0x%016x%s\n", regs.Rbx, dbger.addr2some(regs.Rbx))
	Printf("$rcx   : 0x%016x%s\n", regs.Rcx, dbger.addr2some(regs.Rcx))
	Printf("$rdx   : 0x%016x%s\n", regs.Rdx, dbger.addr2some(regs.Rdx))
	Printf("$rsp   : 0x%016x%s\n", regs.Rsp, dbger.addr2some(regs.Rsp))
	Printf("$rbp   : 0x%016x%s\n", regs.Rbp, dbger.addr2some(regs.Rbp))
	Printf("$rsi   : 0x%016x%s\n", regs.Rsi, dbger.addr2some(regs.Rsi))
	Printf("$rdi   : 0x%016x%s\n", regs.Rdi, dbger.addr2some(regs.Rdi))
	Printf("$rip   : 0x%016x%s\n", rip, dbger.addr2some(rip))
	Printf("$r8    : 0x%016x%s\n", regs.R8, dbger.addr2some(regs.R8))
	Printf("$r9    : 0x%016x%s\n", regs.R9, dbger.addr2some(regs.R9))
	Printf("$r10   : 0x%016x%s\n", regs.R10, dbger.addr2some(regs.R10))
	Printf("$r11   : 0x%016x%s\n", regs.R11, dbger.addr2some(regs.R11))
	Printf("$r12   : 0x%016x%s\n", regs.R12, dbger.addr2some(regs.R12))
	Printf("$r13   : 0x%016x%s\n", regs.R13, dbger.addr2some(regs.R13))
	Printf("$r14   : 0x%016x%s\n", regs.R14, dbger.addr2some(regs.R14))
	Printf("$eflags: 0x%016x\n", regs.Eflags)
	Printf("$cs: %x $ss: %x $ds: %x $es: %x $fs: %x $gs: %x\n",
		regs.Cs, regs.Ss, regs.Ds, regs.Es, regs.Fs, regs.Gs)

	hLine("stack")
	if regs != nil && dbger.arch == 64 {
		data, err := dbger.GetMemory(64, uintptr(regs.Rsp))
		if err != nil {
			LogError("Error while getting stack memory: %v", err)
		} else {
			fmt.Printf("$rsp>")
			for i := 0; i < len(data); i += 8 {
				if i+8 <= len(data) {
					if i != 0 {
						fmt.Printf("     ")
					}
					fmt.Printf("%s0x%016x%s: %s0x%016x%s%s\n", ColorBlue, regs.Rsp+uint64(i), ColorReset, ColorCyan,
						binary.LittleEndian.Uint64(data[i:i+8]), ColorReset, dbger.addr2some(binary.LittleEndian.Uint64(data[i:i+8])))
				}
			}
		}
	}

	hLine("disassembly")
	if regs != nil {
		dbger.disass(rip, 32)
	}

	hLine("back trace")

	return nil
}

func (dbger *TypeDbg) cmdStack(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	var sz uint64 = 8
	var err error
	if len(args[2]) != 0 {
		sz, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return err
		}
	}
	rsp, err := dbger.GetRsp()
	if err != nil {
		return err
	}
	data, err := dbger.GetMemory(uint(sz*8), uintptr(rsp))
	if err != nil {
		LogError("Error while getting stack memory: %v", err)
	} else {
		for i := 0; i < len(data); i += 8 {
			if i+8 <= len(data) {
				fmt.Printf("%s0x%016x%s: %s0x%016x%s%s\n", ColorBlue, rsp+uint64(i), ColorReset, ColorCyan,
					binary.LittleEndian.Uint64(data[i:i+8]), ColorReset, dbger.addr2some(binary.LittleEndian.Uint64(data[i:i+8])))
			}
		}
	}

	return nil
}

func (dbger *TypeDbg) cmdVmmap(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}

	fmt.Println("[start]              [end]              | [size]     | [offset]    | [rwx]  [path]")
	if args[2] != "" {
		for _, p := range procMapsDetail {
			if strings.Contains(p.path, strings.TrimSpace(args[2])) {
				fmt.Printf("0x%016x ~ 0x%016x | 0x%08x | +0x%08x | %s : %s\n", p.start, p.end, (p.end - p.start), p.offset, p.rwx, p.path)
			}
		}
		return nil
	}

	for _, p := range procMapsDetail {
		fmt.Printf("0x%016x ~ 0x%016x | 0x%08x | +0x%08x | %s : %s\n", p.start, p.end, (p.end - p.start), p.offset, p.rwx, p.path)
	}

	return nil
}

func (dbger *TypeDbg) cmdSym(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	return dbger.ListSymbols(args[2])
}

func (dbger *TypeDbg) cmdGot(a interface{}) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}

	pltEntries, gotEntries, err := dbger.AnalyzePLTGOTInfo()
	if err != nil {
		return fmt.Errorf("failed to analyze PLT/GOT: %v", err)
	}

	printf := func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
	}

	printf("Name                        | PLT            | GOT            | GOT value     \n")
	hLine(".rela.plt")

	pltMap := make(map[string]PLTEntry)
	for _, plt := range pltEntries {
		pltMap[plt.OriginalName] = plt
	}

	gotMap := make(map[string]GOTEntry)
	for _, got := range gotEntries {
		if got.Name != "" && !strings.HasPrefix(got.Name, "GOT[") {
			gotMap[got.Name] = got
		}
	}

	processed := make(map[string]bool)

	for _, plt := range pltEntries {
		if processed[plt.OriginalName] {
			continue
		}
		processed[plt.OriginalName] = true

		pltAddr := fmt.Sprintf("0x%012x", plt.Address)
		gotAddr := "Not found"
		gotValue := "Not found"

		if got, exists := gotMap[plt.OriginalName]; exists {
			gotAddr = fmt.Sprintf("0x%012x", got.Address)

			if got.Value != 0 {
				resolved := ""
				if sym, _, err := dbger.ResolveAddrToSymbol(got.Value); err == nil {
					resolved = fmt.Sprintf(" <%s>", sym.Name)
				}
				gotValue = fmt.Sprintf("0x%012x%s", got.Value, resolved)
			} else {
				gotValue = "0x000000000000"
			}
		} else {
			for _, got := range gotEntries {
				if strings.HasPrefix(got.Name, "GOT[") {
					data, err := dbger.GetMemory(8, uintptr(got.Address))
					if err == nil {
						value := binary.LittleEndian.Uint64(data)
						if value != 0 {
							if sym, _, err := dbger.ResolveAddrToSymbol(value); err == nil {
								if strings.Contains(sym.Name, plt.OriginalName) {
									gotAddr = fmt.Sprintf("0x%012x", got.Address)
									resolved := fmt.Sprintf(" <%s>", sym.Name)
									gotValue = fmt.Sprintf("0x%012x%s", value, resolved)
									break
								}
							}
						}
					}
				}
			}
		}

		printf("%-27s | %s | %s | %s\n", plt.OriginalName, pltAddr, gotAddr, gotValue)
	}

	hLine(".rela.dyn")

	for _, got := range gotEntries {
		if got.Name == "" || strings.HasPrefix(got.Name, "GOT[") {
			continue
		}

		if processed[got.Name] {
			continue
		}
		processed[got.Name] = true

		pltAddr := "  Not found   "
		if plt, exists := pltMap[got.Name]; exists {
			pltAddr = fmt.Sprintf("0x%012x", plt.Address)
		}

		gotAddr := fmt.Sprintf("0x%012x", got.Address)
		gotValue := "0x000000000000"

		if got.Value != 0 {
			resolved := ""
			if sym, _, err := dbger.ResolveAddrToSymbol(got.Value); err == nil {
				resolved = fmt.Sprintf(" <%s>", sym.Name)
			}
			gotValue = fmt.Sprintf("0x%012x%s", got.Value, resolved)
		} else {
			data, err := dbger.GetMemory(8, uintptr(got.Address))
			if err == nil {
				value := binary.LittleEndian.Uint64(data)
				if value != 0 {
					resolved := ""
					if sym, _, err := dbger.ResolveAddrToSymbol(value); err == nil {
						resolved = fmt.Sprintf(" <%s>", sym.Name)
					}
					gotValue = fmt.Sprintf("0x%012x%s", value, resolved)
				}
			}
		}

		printf("%-27s | %s | %s | %s\n", got.Name, pltAddr, gotAddr, gotValue)
	}

	return nil
}

func (dbger *TypeDbg) cmdCmd(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	fmt.Println(strings.Join(args, ","))

	handle := exec.Command("/bin/sh", "-c", args[2])
	output, err := handle.CombinedOutput()
	fmt.Println(string(output))
	return err
}

func (dbger *TypeDbg) cmdDisass(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	var addr uint64
	var err error
	if len(args[2]) == 0 {
		addr, err = dbger.GetRip()
		if err != nil {
			return err
		}
		dbger.disass2ret(addr)
		return nil
	} else {
		addr, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return err
		}
	}
	var sz uint64 = 32
	if args[4] != "" {
		sz, err = strconv.ParseUint(args[5], 0, 32)
		if err != nil {
			return err
		}
	}

	dbger.disass(addr, uint(sz))

	return nil
}

func (dbger *TypeDbg) cmdRegs(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	if len(args[2]) != 0 {
		val, err := dbger.GetRegs(args[2])
		if err != nil {
			return err
		}
		Printf("%s = 0x%016x\n", args[2], val)

		return nil
	}
	var regs *unix.PtraceRegs
	var err error

	regs, err = dbger.getRegs()
	if err != nil {
		return err
	}

	if regs == nil {
		return errors.New("nil registers")
	}

	rip, err := dbger.GetRip()
	if err != nil {
		return err
	}

	Printf("$rax   : 0x%016x%s\n", regs.Rax, dbger.addr2some(regs.Rax))
	Printf("$rbx   : 0x%016x%s\n", regs.Rbx, dbger.addr2some(regs.Rbx))
	Printf("$rcx   : 0x%016x%s\n", regs.Rcx, dbger.addr2some(regs.Rcx))
	Printf("$rdx   : 0x%016x%s\n", regs.Rdx, dbger.addr2some(regs.Rdx))
	Printf("$rsp   : 0x%016x%s\n", regs.Rsp, dbger.addr2some(regs.Rsp))
	Printf("$rbp   : 0x%016x%s\n", regs.Rbp, dbger.addr2some(regs.Rbp))
	Printf("$rsi   : 0x%016x%s\n", regs.Rsi, dbger.addr2some(regs.Rsi))
	Printf("$rdi   : 0x%016x%s\n", regs.Rdi, dbger.addr2some(regs.Rdi))
	Printf("$rip   : 0x%016x%s\n", rip, dbger.addr2some(rip))
	Printf("$r8    : 0x%016x%s\n", regs.R8, dbger.addr2some(regs.R8))
	Printf("$r9    : 0x%016x%s\n", regs.R9, dbger.addr2some(regs.R9))
	Printf("$r10   : 0x%016x%s\n", regs.R10, dbger.addr2some(regs.R10))
	Printf("$r11   : 0x%016x%s\n", regs.R11, dbger.addr2some(regs.R11))
	Printf("$r12   : 0x%016x%s\n", regs.R12, dbger.addr2some(regs.R12))
	Printf("$r13   : 0x%016x%s\n", regs.R13, dbger.addr2some(regs.R13))
	Printf("$r14   : 0x%016x%s\n", regs.R14, dbger.addr2some(regs.R14))
	Printf("$eflags: 0x%016x\n", regs.Eflags)
	Printf("$cs: %x $ss: %x $ds: %x $es: %x $fs: %x $gs: %x\n",
		regs.Cs, regs.Ss, regs.Ds, regs.Es, regs.Fs, regs.Gs)

	return nil
}

func (dbger *TypeDbg) cmdStep(_ interface{}) error {
	err := dbger.Step()
	if err != nil {
		return err
	}
	if dbger.isStart {
		cls()
		dbger.cmdContext(nil)
	}

	return nil
}
