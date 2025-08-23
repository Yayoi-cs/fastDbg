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
	"time"
)

var cmd = map[string]func(*TypeDbg, interface{}) error{
	`^\s*(b|break|B|BREAK)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`: (*TypeDbg).cmdBreak,
	`^\s*(enable)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`:          (*TypeDbg).cmdEnable,
	`^\s*(disable)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`:         (*TypeDbg).cmdDisable,
	`^\s*(disass)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`:          (*TypeDbg).cmdDisass,
	`^\s*(r|run|R|RUN)(?:\s+(.+))?$`:                                     (*TypeDbg).cmdRun,
	`^\s*(regs)(?:\s+(.+))?$`:                                            (*TypeDbg).cmdRegs,
	`^\s*(!)(.+)$`:                                                       (*TypeDbg).cmdCmd,
	`^\s*(c|continue|cont|C|CONTINUE|CONT)\s*$`:                          (*TypeDbg).cmdContinue,
	`^\s*(context|CONTEXT)\s*$`:                                          (*TypeDbg).cmdContext,
	`^\s*(vmmap|VMMAP)(\s+\w+)*\s*$`:                                     (*TypeDbg).cmdVmmap,
	`^\s*(sym|symbol|SYM|SYMBOL)(\s+\w+)*\s*$`:                           (*TypeDbg).cmdSym,
	`^\s*(db|xxd)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`:         (*TypeDbg).cmdDumpByte,
	`^\s*(dd|xxd\s+dword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`: (*TypeDbg).cmdDumpDword,
	`^\s*(dq|xxd\s+qword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`: (*TypeDbg).cmdDumpQword,
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
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	tmpDbger, err := Run(dbger.path, args[2:]...)
	if err != nil {
		return err
	}
	mainDbger = *tmpDbger

	for _, addr := range tmpBps {
		_, err = dbger.NewBp(addr, dbger.pid)
		if err != nil {
			return err
		}
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

	_, err = dbger.wait()
	if err != nil {
		return err
	}

	cls()

	dbger.cmdContext(nil)

	return err
}

func (dbger *TypeDbg) cmdContext(a interface{}) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}

	hLine("registers")

	if !dbger.isProcessAlive() {
		return errors.New("process is not alive")
	}

	if !dbger.isStopped() {
		Printf("Process is running, stopping...\n")
		if err := dbger.stop(); err != nil {
			return fmt.Errorf("failed to stop process: %v", err)
		}

		timeout := time.After(1 * time.Second)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		stopped := false
		for !stopped {
			select {
			case <-timeout:
				return errors.New("timeout waiting for process to stop")
			case <-ticker.C:
				stopped = dbger.isStopped()
			}
		}
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

	if dbger.arch == 64 {
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
	}
	Printf("$cs: %x $ss: %x $ds: %x $es: %x $fs: %x $gs: %x\n",
		regs.Cs, regs.Ss, regs.Ds, regs.Es, regs.Fs, regs.Gs)

	hLine("stack")
	if regs != nil && dbger.arch == 64 {
		data, err := dbger.GetMemory(64, uintptr(regs.Rsp))
		if err != nil {
			LogError("Error while getting stack memory: %v", err)
		} else {
			for i := 0; i < len(data); i += 8 {
				if i+8 <= len(data) {
					Printf("0x%016x: 0x%016x\n", regs.Rsp+uint64(i),
						binary.LittleEndian.Uint64(data[i:i+8]))
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

	return nil
}

func (dbger *TypeDbg) cmdRegs(a interface{}) error {

	return nil
}
