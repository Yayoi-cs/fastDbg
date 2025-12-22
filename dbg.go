package main

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var mainDbger TypeDbg = TypeDbg{
	pid:      0,
	path:     "",
	isAttach: false,
	rip:      0,
	isStart:  false,
	arch:     64,
	isBp:     false,
	rpc:      nil,
}

type TypeDbg struct {
	pid      int
	path     string
	isAttach bool
	rip      uint64
	isStart  bool
	arch     int
	isBp     bool
	rpc      *doSysRPC
}

var procMapsDetail []*proc

type proc struct {
	start  uint64
	end    uint64
	r      bool
	w      bool
	x      bool
	offset uint64
	path   string
}

func (dbger *TypeDbg) isProcessAlive() bool {
	if dbger.pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", dbger.pid))
	return err == nil
}

func (dbger *TypeDbg) isStopped() bool {
	if !dbger.isProcessAlive() {
		return false
	}

	path := fmt.Sprintf("/proc/%d/stat", dbger.pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return false
	}

	state := fields[2]
	return state == "t" || state == "T"
}

func (dbger *TypeDbg) isProcessTraced() bool {
	statusFile := fmt.Sprintf("/proc/%d/status", dbger.pid)
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return false
	}

	return !strings.Contains(string(data), "TracerPid:\t0")
}

func (dbger *TypeDbg) getExecutablePath() (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", dbger.pid)
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve executable path: %v", err)
	}

	absPath, err := filepath.Abs(realPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %v", err)
	}

	return absPath, nil
}

func (dbger *TypeDbg) loadBase() error {
	procMapsDetail = []*proc{}
	rgx := `^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]+)\s+([0-9a-f]+)\s+([0-9a-f]+:[0-9a-f]+)\s+(\d+)(?:\s+(.*))?$`

	regex, err := regexp.Compile(rgx)
	if err != nil {
		return err
	}

	fileName := fmt.Sprintf("/proc/%d/maps", dbger.pid)
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := regex.FindStringSubmatch(scanner.Text())
		if len(match) < 7 {
			continue
		}
		startAddr, _ := strconv.ParseUint(match[1], 16, 64)
		endAddr, _ := strconv.ParseUint(match[2], 16, 64)
		offset, _ := strconv.ParseUint(match[4], 16, 64)
		pathname := ""
		if len(match) > 7 && match[7] != "" {
			pathname = strings.TrimSpace(match[7])
		}

		newMap := proc{
			start:  startAddr,
			end:    endAddr,
			r:      strings.Contains(match[3], "r"),
			w:      strings.Contains(match[3], "w"),
			x:      strings.Contains(match[3], "x"),
			offset: offset,
			path:   pathname,
		}
		procMapsDetail = append(procMapsDetail, &newMap)
	}

	return nil
}

func Run(bin string, args ...string) (*TypeDbg, error) {
	absPath := bin
	if strings.HasPrefix(bin, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		absPath = filepath.Join(home, bin[1:])
	} else if strings.HasPrefix(bin, "./") || !strings.HasPrefix(bin, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		absPath = filepath.Join(cwd, bin)
	}

	absPath, err := filepath.Abs(absPath)
	if err != nil {
		return nil, err
	}

	f, err := elf.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var arch int
	switch f.Class {
	case elf.ELFCLASS32:
		arch = 32
	case elf.ELFCLASS64:
		arch = 64
	default:
		return nil, errors.New("unknown ELF class")
	}

	dbger := &TypeDbg{
		pid:      -1,
		path:     absPath,
		isAttach: false,
		rip:      0,
		isStart:  true,
		arch:     arch,
		isBp:     false,
		rpc:      doSyscallWorker(),
	}

	doSyscallErr(dbger.rpc, func() error {
		cmd := exec.Command(absPath, args...)

		cmd.SysProcAttr = &unix.SysProcAttr{
			Ptrace: true,
		}

		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err = cmd.Start(); err != nil {
			return err
		}
		dbger.pid = cmd.Process.Pid
		Printf("%s started with PID:%d\n", absPath, dbger.pid)

		return nil
	})

	_, err = dbger.wait()
	if err != nil {
		return nil, err
	}

	dbger.rip, err = dbger.GetRip()
	if err != nil {
		return nil, err
	}

	err = dbger.loadBase()

	return dbger, nil
}

func Attach(pid int) (*TypeDbg, error) {
	dbger := &TypeDbg{
		pid:      pid,
		path:     "",
		isAttach: true,
		rip:      0,
		isStart:  true,
		arch:     64,
		rpc:      doSyscallWorker(),
	}

	if !dbger.isProcessAlive() {
		return nil, fmt.Errorf("process %d does not exist", pid)
	}

	if dbger.isProcessTraced() {
		return nil, fmt.Errorf("process %d is already being traced", pid)
	}

	exePath, err := dbger.getExecutablePath()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}
	dbger.path = exePath
	Printf("Resolved executable: %s\n", exePath)

	f, err := elf.Open(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %v", err)
	}
	defer f.Close()

	switch f.Class {
	case elf.ELFCLASS32:
		dbger.arch = 32
	case elf.ELFCLASS64:
		dbger.arch = 64
	default:
		return nil, errors.New("unknown ELF class")
	}

	err = doSyscallErr(dbger.rpc, func() error {
		return unix.PtraceAttach(pid)
	})
	if err != nil {
		return nil, dbger.formatPtraceError("attach", err)
	}

	Printf("attached to PID:%d\n", pid)

	_, err = dbger.wait()
	if err != nil {
		waitErr := err
		detachErr := doSyscallErr(dbger.rpc, func() error {
			return unix.PtraceDetach(pid)
		})
		if detachErr != nil {
			return nil, fmt.Errorf("wait failed: %v (detach also failed: %v)", waitErr, detachErr)
		}
		return nil, fmt.Errorf("wait failed: %v", waitErr)
	}

	dbger.rip, err = dbger.GetRip()
	if err != nil {
		return nil, err
	}

	err = dbger.loadBase()
	return dbger, nil
}

func (dbger *TypeDbg) Detach() error {
	if dbger.pid <= 0 {
		return errors.New("invalid PID")
	}

	wasStopped := dbger.isStopped()

	err := doSyscallErr(dbger.rpc, func() error {
		return unix.PtraceDetach(dbger.pid)
	})
	if err != nil {
		return err
	}

	if wasStopped {
		unix.Kill(dbger.pid, unix.SIGCONT)
	}

	Printf("detached from PID:%d\n", dbger.pid)
	return nil
}

func (dbger *TypeDbg) interrupt() error {
	return doSyscallErr(dbger.rpc, func() error {
		return unix.PtraceInterrupt(dbger.pid)
	})
}

func (dbger *TypeDbg) wait() (unix.WaitStatus, error) {
	var ws unix.WaitStatus
	var err error

	err = doSyscallErr(dbger.rpc, func() error {
		_, err = unix.Wait4(dbger.pid, &ws, 0, nil)
		return err
	})

	if err != nil {
		return 0, dbger.formatPtraceError("wait", err)
	}

	if ws.Exited() {
		Printf("PID:%d exited with status %d\n", dbger.pid, ws.ExitStatus())
		dbger.isStart = false
		return ws, nil
	}
	if ws.CoreDump() {
		Printf("Segmentation fault (SIGSEGV): %d\n", dbger.pid)
	}

	if ws.Stopped() {
		rip, err := dbger.GetRip()
		if err == nil {
			dbger.rip = rip
			dbger.checkBreakpoint(rip)
		}
	}

	return ws, nil
}

func (dbger *TypeDbg) checkBreakpoint(rip uint64) bool {
	checkAddr := rip - 1
	for i, b := range Bps {
		if b.addr == uintptr(checkAddr) && b.isEnable {
			Printf("stopped at breakpoint %d @ %x\n", i, checkAddr)
			return true
		}
	}
	return false
}

func (dbger *TypeDbg) stopWait() (unix.WaitStatus, error) {
	err := dbger.stop()
	if err != nil {
		return 0, err
	}
	return dbger.wait()
}

func (dbger *TypeDbg) Continue() error {
	if !dbger.isProcessAlive() {
		return errors.New("process is not alive")
	}

	rip, err := dbger.GetRip()
	if err != nil {
		return err
	}

	bp, ok := func(rip uint64) (*TypeBp, bool) {
		for _, b := range Bps {
			if b.addr == uintptr(rip) && b.isEnable {
				return &b, true
			}
		}
		return nil, false
	}(rip)

	if ok {
		if err := bp.disableBp(dbger); err != nil {
			return err
		}
		if err := dbger.SetRip(rip); err != nil {
			return err
		}
		err = doSyscallErr(dbger.rpc, func() error {
			return unix.PtraceSingleStep(dbger.pid)
		})
		if err != nil {
			return err
		}
		if _, err = dbger.wait(); err != nil {
			return err
		}

		err = bp.enableBp(dbger)
		if err != nil {
			return err
		}
	}

	return doSyscallErr(dbger.rpc, func() error {
		return unix.PtraceCont(dbger.pid, 0)
	})
}

func (dbger *TypeDbg) stop() error {
	return doSyscallErr(dbger.rpc, func() error {
		return unix.Kill(dbger.pid, unix.SIGSTOP)
	})
}

func (dbger *TypeDbg) Step() error {
	if !dbger.isProcessAlive() {
		return errors.New("process is not alive")
	}

	rip, err := dbger.GetRip()
	if err != nil {
		return err
	}

	bp, ok := func(rip uint64) (*TypeBp, bool) {
		for _, b := range Bps {
			if b.addr == uintptr(rip) && b.isEnable {
				return &b, true
			}
		}
		return nil, false
	}(rip)

	if ok {
		if err := bp.disableBp(dbger); err != nil {
			return err
		}
		if err := dbger.SetRip(rip); err != nil {
			return err
		}
		err = doSyscallErr(dbger.rpc, func() error {
			return unix.PtraceSingleStep(dbger.pid)
		})
		if err != nil {
			return err
		}
		if _, err = dbger.wait(); err != nil {
			return err
		}

		err = bp.enableBp(dbger)
		if err != nil {
			return err
		}
	} else {
		return doSyscallErr(dbger.rpc, func() error {
			return unix.PtraceSingleStep(dbger.pid)
		})
		if _, err = dbger.wait(); err != nil {
			return err
		}
	}

	return nil
}

func (dbger *TypeDbg) formatPtraceError(operation string, err error) error {
	switch err {
	case unix.ESRCH:
		return fmt.Errorf("%s failed: process %d does not exist or exited", operation, dbger.pid)
	case unix.EPERM:
		return fmt.Errorf("%s failed: permission denied", operation)
	case unix.EBUSY:
		return fmt.Errorf("%s failed: process is busy", operation)
	default:
		return fmt.Errorf("%s failed: %v", operation, err)
	}
}

func (dbger *TypeDbg) GetProcMaps() []*proc {
	return procMapsDetail
}

func (dbger *TypeDbg) DisassOne(addr uintptr) (*string, error) {
	return dbger.disassOne(addr)
}

func (dbger *TypeDbg) IsActive() bool {
	return dbger.isStart && dbger.isProcessAlive()
}

func (dbger *TypeDbg) Kill() error {
	if dbger.pid <= 0 {
		return nil
	}

	// Kill the process if it's still alive
	if dbger.isProcessAlive() {
		err := doSyscallErr(dbger.rpc, func() error {
			return unix.Kill(dbger.pid, unix.SIGKILL)
		})
		if err != nil {
			return fmt.Errorf("failed to kill process: %v", err)
		}

		// Wait for process to exit
		doSyscallErr(dbger.rpc, func() error {
			unix.Wait4(dbger.pid, nil, 0, nil)
			return nil
		})
	}

	// Close the RPC goroutine
	if dbger.rpc != nil {
		dbger.rpc.closeSyscall()
		dbger.rpc = nil
	}

	dbger.isStart = false
	dbger.pid = 0

	return nil
}
