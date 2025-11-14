package main

import (
	"encoding/binary"
	"errors"
	"fastDbg/ebpf"
	"fmt"
	"golang.org/x/sys/unix"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type cmdHandler struct {
	regex *regexp.Regexp
	fn    func(*TypeDbg, interface{}) error
}

var compiledCmds = []cmdHandler{
	{regexp.MustCompile(`^\s*(b|break|B|BREAK)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdBreak},
	{regexp.MustCompile(`^\s*(b|break|B|BREAK)\s+(pie|PIE)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdBreakPie},
	{regexp.MustCompile(`^\s*(enable)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdEnable},
	{regexp.MustCompile(`^\s*(disable)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdDisable},
	{regexp.MustCompile(`^\s*(disass)(\s+(0[xx][0-9a-fa-f]+|0[0-7]+|[1-9][0-9]*|0))?(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*TypeDbg).cmdDisass},
	{regexp.MustCompile(`^\s*(stackframe|stkf|STACKFRAME|STKF)(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*TypeDbg).cmdStackFrame},
	{regexp.MustCompile(`^\s*(p|print|P|PRINT)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdPrint},
	{regexp.MustCompile(`^\s*(r|run|R|RUN)(?:\s+(.+))?$`), (*TypeDbg).cmdRun},
	{regexp.MustCompile(`^\s*(s|start|S|START)(?:\s+(.+))?$`), (*TypeDbg).cmdStart},
	{regexp.MustCompile(`^\s*(regs)(?:\s+(.+))?$`), (*TypeDbg).cmdRegs},
	{regexp.MustCompile(`^\s*(!)(.+)$`), (*TypeDbg).cmdCmd},
	{regexp.MustCompile(`^\s*(c|continue|cont|C|CONTINUE|CONT)\s*$`), (*TypeDbg).cmdContinue},
	{regexp.MustCompile(`^\s*(step|STEP)\s*$`), (*TypeDbg).cmdStep},
	{regexp.MustCompile(`^\s*(context|CONTEXT)\s*$`), (*TypeDbg).cmdContext},
	{regexp.MustCompile(`^\s*(color|COLOR)\s*$`), (*TypeDbg).cmdColor},
	{regexp.MustCompile(`^\s*(stack|stk|STACK|STK)(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*TypeDbg).cmdStack},
	{regexp.MustCompile(`^\s*(vmmap|VMMAP)(\s+\w+)*\s*$`), (*TypeDbg).cmdVmmap},
	{regexp.MustCompile(`^\s*(sym|symbol|SYM|SYMBOL)(\s+\w+)*\s*$`), (*TypeDbg).cmdSym},
	{regexp.MustCompile(`^\s*(got|GOT)\s*$`), (*TypeDbg).cmdGot},
	{regexp.MustCompile(`^\s*(bins|BINS)\s*$`), (*TypeDbg).cmdBins},
	{regexp.MustCompile(`^\s*(vis|visual-heap|VIS|VISUAL-HEAP)\s*$`), (*TypeDbg).cmdVisualHeap},
	{regexp.MustCompile(`^\s*(set32)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdSet32},
	{regexp.MustCompile(`^\s*(set16)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdSet16},
	{regexp.MustCompile(`^\s*(set8)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdSet8},
	{regexp.MustCompile(`^\s*(set)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdSet},
	{regexp.MustCompile(`^\s*(xor)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*TypeDbg).cmdXor},
	{regexp.MustCompile(`^\s*(tel|telescope)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*TypeDbg).cmdTelescope},
	{regexp.MustCompile(`^\s*(db|xxd)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*TypeDbg).cmdDumpByte},
	{regexp.MustCompile(`^\s*(dd|xxd\s+dword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*TypeDbg).cmdDumpDword},
	{regexp.MustCompile(`^\s*(dq|xxd\s+qword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*TypeDbg).cmdDumpQword},
	{regexp.MustCompile(`^\s*(bt|backtrace|BT|BACKTRACE)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*TypeDbg).cmdBacktrace},
}

func (dbger *TypeDbg) cmdExec(req string) error {
	for _, handler := range compiledCmds {
		if m := handler.regex.FindStringSubmatch(req); m != nil {
			return handler.fn(dbger, m)
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
		fmt.Printf("booked breakpoint %s%d%s @ %s0x%016x%s\n", ColorCyan, len(tmpBps), ColorReset, ColorCyan, addr, ColorReset)
		return nil
	}

	_, err = dbger.NewBp(uintptr(addr), dbger.pid)
	if err != nil {
		return err
	} else {
		fmt.Printf("new breakpoint at %s0x%016x%s\n", ColorCyan, addr, ColorReset)
		return nil
	}
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
		fmt.Printf("booked breakpoint %s%d%s @ %s0x%016x%s\n", ColorCyan, len(tmpBps), ColorReset, ColorCyan, addr, ColorReset)
		return nil
	}

	_, err = dbger.NewBp(uintptr(addr), dbger.pid)
	if err != nil {
		return err
	} else {
		fmt.Printf("new breakpoint at %s0x%016x%s\n", ColorCyan, addr, ColorReset)
		return nil
	}
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

func (dbger *TypeDbg) cmdPrint(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	val, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	fmt.Printf("HEX: %s0x%x%s DEC: %s%d%s OCT: %s%o%s BIN: %s%b%s\n", ColorCyan, val, ColorReset, ColorCyan, val, ColorReset, ColorCyan, val, ColorReset, ColorCyan, val, ColorReset)

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
	ebpf.NewTrace(dbger.pid)

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
	if ebpf.MapFlag {
		dbger.loadBase()
		ebpf.MapFlag = false
	}

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

	fmt.Printf("$rax   : %s0x%016x%s\n", dbger.addr2color(regs.Rax), regs.Rax, dbger.addr2some(regs.Rax))
	fmt.Printf("$rbx   : %s0x%016x%s\n", dbger.addr2color(regs.Rbx), regs.Rbx, dbger.addr2some(regs.Rbx))
	fmt.Printf("$rcx   : %s0x%016x%s\n", dbger.addr2color(regs.Rcx), regs.Rcx, dbger.addr2some(regs.Rcx))
	fmt.Printf("$rdx   : %s0x%016x%s\n", dbger.addr2color(regs.Rdx), regs.Rdx, dbger.addr2some(regs.Rdx))
	fmt.Printf("$rsp   : %s0x%016x%s\n", dbger.addr2color(regs.Rsp), regs.Rsp, dbger.addr2some(regs.Rsp))
	fmt.Printf("$rbp   : %s0x%016x%s\n", dbger.addr2color(regs.Rbp), regs.Rbp, dbger.addr2some(regs.Rbp))
	fmt.Printf("$rsi   : %s0x%016x%s\n", dbger.addr2color(regs.Rsi), regs.Rsi, dbger.addr2some(regs.Rsi))
	fmt.Printf("$rdi   : %s0x%016x%s\n", dbger.addr2color(regs.Rdi), regs.Rdi, dbger.addr2some(regs.Rdi))
	fmt.Printf("$rip   : %s0x%016x%s\n", dbger.addr2color(rip), rip, dbger.addr2some(rip))
	fmt.Printf("$r8    : %s0x%016x%s\n", dbger.addr2color(regs.R8), regs.R8, dbger.addr2some(regs.R8))
	fmt.Printf("$r9    : %s0x%016x%s\n", dbger.addr2color(regs.R9), regs.R9, dbger.addr2some(regs.R9))
	fmt.Printf("$r10   : %s0x%016x%s\n", dbger.addr2color(regs.R10), regs.R10, dbger.addr2some(regs.R10))
	fmt.Printf("$r11   : %s0x%016x%s\n", dbger.addr2color(regs.R11), regs.R11, dbger.addr2some(regs.R11))
	fmt.Printf("$r12   : %s0x%016x%s\n", dbger.addr2color(regs.R12), regs.R12, dbger.addr2some(regs.R12))
	fmt.Printf("$r13   : %s0x%016x%s\n", dbger.addr2color(regs.R13), regs.R13, dbger.addr2some(regs.R13))
	fmt.Printf("$r14   : %s0x%016x%s\n", dbger.addr2color(regs.R14), regs.R14, dbger.addr2some(regs.R14))
	fmt.Printf("$eflags: 0x%016x\n", regs.Eflags)
	fmt.Printf("$cs: %x $ss: %x $ds: %x $es: %x $fs: %x $gs: %x\n",
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
					address := binary.LittleEndian.Uint64(data[i : i+8])
					fmt.Printf("%s0x%016x%s: %s0x%016x%s%s\n", ColorReadWrite, regs.Rsp+uint64(i), ColorReset, dbger.addr2color(address),
						address, ColorReset, dbger.addr2some(address))
				}
			}
		}
	}

	hLine("disassembly")
	if regs != nil {
		dbger.disass(rip, 32)
	}

	hLine("back trace")
	btArgs := []string{"backtrace", "", ""}
	dbger.backtrace(btArgs, false)

	hLineRaw()
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
				rwx := ""
				if p.r {
					rwx += "r"
				} else {
					rwx += " "
				}
				if p.w {
					rwx += "w"
				} else {
					rwx += " "
				}
				if p.x {
					rwx += "x"
				} else {
					rwx += " "
				}
				fmt.Printf("%s0x%016x ~ 0x%016x | 0x%08x | +0x%08x | %s : %s%s\n", dbger.addr2color(p.start), p.start, p.end, (int)(p.end-p.start), p.offset, rwx, p.path, ColorReset)
			}
		}
		return nil
	}

	for _, p := range procMapsDetail {
		rwx := ""
		if p.r {
			rwx += "r"
		} else {
			rwx += " "
		}
		if p.w {
			rwx += "w"
		} else {
			rwx += " "
		}
		if p.x {
			rwx += "x"
		} else {
			rwx += " "
		}
		fmt.Printf("%s0x%016x ~ 0x%016x | 0x%08x | +0x%08x | %s : %s%s\n", dbger.addr2color(p.start), p.start, p.end, (p.end - p.start), p.offset, rwx, p.path, ColorReset)
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

			// Always read from process memory for accurate runtime values (especially for PIE)
			data, err := dbger.GetMemory(8, uintptr(got.Address))
			if err == nil && len(data) >= 8 {
				value := binary.LittleEndian.Uint64(data)
				resolved := ""
				if value != 0 {
					if sym, _, err := dbger.ResolveAddrToSymbol(value); err == nil {
						resolved = fmt.Sprintf(" <%s>", sym.Name)
					}
				}
				gotValue = fmt.Sprintf("0x%012x%s", value, resolved)
			} else {
				gotValue = "0x000000000000"
			}
		} else {
			// Fallback: search through unnamed GOT entries
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

		// Always read from process memory for accurate runtime values (especially for PIE)
		data, err := dbger.GetMemory(8, uintptr(got.Address))
		if err == nil && len(data) >= 8 {
			value := binary.LittleEndian.Uint64(data)
			resolved := ""
			if value != 0 {
				if sym, _, err := dbger.ResolveAddrToSymbol(value); err == nil {
					resolved = fmt.Sprintf(" <%s>", sym.Name)
				}
			}
			gotValue = fmt.Sprintf("0x%012x%s", value, resolved)
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

	fmt.Printf("$rax   : %s0x%016x%s\n", dbger.addr2color(regs.Rax), regs.Rax, dbger.addr2some(regs.Rax))
	fmt.Printf("$rbx   : %s0x%016x%s\n", dbger.addr2color(regs.Rbx), regs.Rbx, dbger.addr2some(regs.Rbx))
	fmt.Printf("$rcx   : %s0x%016x%s\n", dbger.addr2color(regs.Rcx), regs.Rcx, dbger.addr2some(regs.Rcx))
	fmt.Printf("$rdx   : %s0x%016x%s\n", dbger.addr2color(regs.Rdx), regs.Rdx, dbger.addr2some(regs.Rdx))
	fmt.Printf("$rsp   : %s0x%016x%s\n", dbger.addr2color(regs.Rsp), regs.Rsp, dbger.addr2some(regs.Rsp))
	fmt.Printf("$rbp   : %s0x%016x%s\n", dbger.addr2color(regs.Rbp), regs.Rbp, dbger.addr2some(regs.Rbp))
	fmt.Printf("$rsi   : %s0x%016x%s\n", dbger.addr2color(regs.Rsi), regs.Rsi, dbger.addr2some(regs.Rsi))
	fmt.Printf("$rdi   : %s0x%016x%s\n", dbger.addr2color(regs.Rdi), regs.Rdi, dbger.addr2some(regs.Rdi))
	fmt.Printf("$rip   : %s0x%016x%s\n", dbger.addr2color(rip), rip, dbger.addr2some(rip))
	fmt.Printf("$r8    : %s0x%016x%s\n", dbger.addr2color(regs.R8), regs.R8, dbger.addr2some(regs.R8))
	fmt.Printf("$r9    : %s0x%016x%s\n", dbger.addr2color(regs.R9), regs.R9, dbger.addr2some(regs.R9))
	fmt.Printf("$r10   : %s0x%016x%s\n", dbger.addr2color(regs.R10), regs.R10, dbger.addr2some(regs.R10))
	fmt.Printf("$r11   : %s0x%016x%s\n", dbger.addr2color(regs.R11), regs.R11, dbger.addr2some(regs.R11))
	fmt.Printf("$r12   : %s0x%016x%s\n", dbger.addr2color(regs.R12), regs.R12, dbger.addr2some(regs.R12))
	fmt.Printf("$r13   : %s0x%016x%s\n", dbger.addr2color(regs.R13), regs.R13, dbger.addr2some(regs.R13))
	fmt.Printf("$r14   : %s0x%016x%s\n", dbger.addr2color(regs.R14), regs.R14, dbger.addr2some(regs.R14))
	fmt.Printf("$eflags: 0x%016x\n", regs.Eflags)
	fmt.Printf("$cs: %x $ss: %x $ds: %x $es: %x $fs: %x $gs: %x\n",
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

func (dbger *TypeDbg) cmdColor(_ interface{}) error {
	fmt.Printf("%s[r  ]: readonly				%s\n", ColorRead, ColorReset)
	fmt.Printf("%s[ w ]: writeonly				%s\n", ColorWrite, ColorReset)
	fmt.Printf("%s[  x]: executable				%s\n", ColorExecutable, ColorReset)
	fmt.Printf("%s[rw ]: read/write				%s\n", ColorReadWrite, ColorReset)
	fmt.Printf("%s[r x]: read/executable			%s\n", ColorReadExecutable, ColorReset)
	fmt.Printf("%s[rwx]: read/write/executable	%s\n", ColorReadWriteExecutable, ColorReset)
	fmt.Printf("%s[---]: fault					%s\n", ColorDefault, ColorReset)
	return nil
}

func (dbger *TypeDbg) cmdBacktrace(a interface{}) error {
	return dbger.backtrace(a, true)
}

func (dbger *TypeDbg) backtrace(a interface{}, standalone bool) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}

	if !dbger.isProcessAlive() {
		return errors.New("process is not alive")
	}

	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	maxDepth := 20
	var err error

	if len(args) > 2 && len(args[2]) != 0 {
		depth, err := strconv.ParseUint(args[2], 0, 64)
		if err != nil {
			return fmt.Errorf("invalid depth: %v", err)
		}
		maxDepth = int(depth)
	}

	regs, err := dbger.getRegs()
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

	rbp := regs.Rbp

	frameNum := 0
	fmt.Printf("#%-2d %s0x%016x%s", frameNum, dbger.addr2color(rip), rip, ColorReset)

	sym, offset, err := dbger.ResolveAddrToSymbol(rip)
	if err == nil && sym != nil {
		if offset == 0 {
			fmt.Printf(" in %s()\n", sym.Name)
		} else {
			fmt.Printf(" in %s()+%d\n", sym.Name, offset)
		}
	} else {
		fmt.Printf("\n")
	}

	visited := make(map[uint64]bool)
	visited[rbp] = true

	for frameNum = 1; frameNum < maxDepth; frameNum++ {
		if rbp == 0 || rbp%8 != 0 {
			break
		}

		ripData, err := dbger.GetMemory(8, uintptr(rbp+8))
		if err != nil {
			break
		}

		if len(ripData) < 8 {
			break
		}

		savedRip := binary.LittleEndian.Uint64(ripData)

		if savedRip == 0 {
			break
		}

		fmt.Printf("#%-2d %s0x%016x%s", frameNum, dbger.addr2color(savedRip), savedRip, ColorReset)

		sym, offset, err := dbger.ResolveAddrToSymbol(savedRip)
		if err == nil && sym != nil {
			if offset == 0 {
				fmt.Printf(" in %s()\n", sym.Name)
			} else {
				fmt.Printf(" in %s()+%d\n", sym.Name, offset)
			}
		} else {
			fmt.Printf("\n")
		}

		rbpData, err := dbger.GetMemory(8, uintptr(rbp))
		if err != nil {
			break
		}

		if len(rbpData) < 8 {
			break
		}

		prevRbp := binary.LittleEndian.Uint64(rbpData)
		if visited[prevRbp] {
			break
		}
		if prevRbp <= rbp {
			break
		}

		visited[prevRbp] = true
		rbp = prevRbp
	}

	return nil
}

func (dbger *TypeDbg) cmdStackFrame(a interface{}) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}

	if !dbger.isProcessAlive() {
		return errors.New("process is not alive")
	}

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

	regs, err := dbger.getRegs()
	if err != nil {
		return err
	}

	if regs == nil {
		return errors.New("nil registers")
	}

	rsp := regs.Rsp
	rbp := regs.Rbp

	type FrameInfo struct {
		frameNum int
		rbpAddr  uint64
		ripAddr  uint64
		rbpValue uint64
		ripValue uint64
	}

	frames := []FrameInfo{}
	currentRbp := rbp
	visited := make(map[uint64]bool)

	for frameNum := 0; frameNum < 20; frameNum++ {
		if currentRbp == 0 || currentRbp%8 != 0 {
			break
		}

		if visited[currentRbp] {
			break
		}
		visited[currentRbp] = true

		frame := FrameInfo{
			frameNum: frameNum,
			rbpAddr:  currentRbp,
			ripAddr:  currentRbp + 8,
		}

		rbpData, err := dbger.GetMemory(8, uintptr(currentRbp))
		if err == nil && len(rbpData) >= 8 {
			frame.rbpValue = binary.LittleEndian.Uint64(rbpData)
		}

		ripData, err := dbger.GetMemory(8, uintptr(currentRbp+8))
		if err == nil && len(ripData) >= 8 {
			frame.ripValue = binary.LittleEndian.Uint64(ripData)
		}

		frames = append(frames, frame)

		if frame.rbpValue == 0 || frame.rbpValue <= currentRbp {
			break
		}
		currentRbp = frame.rbpValue
	}

	data, err := dbger.GetMemory(uint(sz*8), uintptr(rsp))
	if err != nil {
		return fmt.Errorf("error while getting stack memory: %v", err)
	}

	for i := 0; i < len(data); i += 8 {
		if i+8 > len(data) {
			break
		}

		addr := rsp + uint64(i)
		value := binary.LittleEndian.Uint64(data[i : i+8])

		annotation := ""
		for _, frame := range frames {
			if addr == frame.rbpAddr {
				annotation = fmt.Sprintf(" <- frame #%d rbp", frame.frameNum)
				break
			} else if addr == frame.ripAddr {
				annotation = fmt.Sprintf(" <- frame #%d ret", frame.frameNum)
				if sym, offset, err := dbger.ResolveAddrToSymbol(value); err == nil && sym != nil {
					if offset == 0 {
						annotation += fmt.Sprintf(" (%s)", sym.Name)
					} else {
						annotation += fmt.Sprintf(" (%s+%d)", sym.Name, offset)
					}
				}
				break
			}
		}

		fmt.Printf("%s0x%016x%s: %s0x%016x%s%s%s%s\n",
			ColorBlue, addr, ColorReset,
			dbger.addr2color(value), value, ColorReset,
			dbger.addr2some(value),
			ColorReadWriteExecutable, annotation)
	}

	return nil
}

func (dbger *TypeDbg) cmdSet(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	val, err := strconv.ParseUint(args[3], 0, 64)
	if err != nil {
		return err
	}
	valBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(valBytes, val)
	return dbger.SetMemory(valBytes, uintptr(addr))
}

func (dbger *TypeDbg) cmdSet32(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	val, err := strconv.ParseUint(args[3], 0, 32)
	if err != nil {
		return err
	}
	valBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valBytes, uint32(val))
	return dbger.SetMemory(valBytes, uintptr(addr))
}

func (dbger *TypeDbg) cmdSet16(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	val, err := strconv.ParseUint(args[3], 0, 16)
	if err != nil {
		return err
	}
	valBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(valBytes, uint16(val))
	return dbger.SetMemory(valBytes, uintptr(addr))
}

func (dbger *TypeDbg) cmdSet8(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	val, err := strconv.ParseUint(args[3], 0, 8)
	if err != nil {
		return err
	}
	valBytes := []byte{byte(val)}
	return dbger.SetMemory(valBytes, uintptr(addr))
}

func (dbger *TypeDbg) cmdXor(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	key, err := strconv.ParseUint(args[3], 0, 64)
	if err != nil {
		return err
	}
	memByte, err := dbger.GetMemory(8, uintptr(addr))
	if err != nil {
		return err
	}
	ord := binary.LittleEndian.Uint64(memByte)
	res := ord ^ key
	fmt.Printf("%s%x%s xor %s%x%s -> %s%x%s\n", ColorCyan, ord, ColorReset, ColorCyan, key, ColorReset, ColorCyan, res, ColorReset)
	resBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(resBytes, res)
	return dbger.SetMemory(resBytes, uintptr(addr))
}
