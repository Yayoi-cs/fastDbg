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
	"sync"
)

var ptraceMutex sync.Mutex

var mainDbger TypeDbg = TypeDbg{
	pid:  0,
	path: "", isAttach: false,
	rip:     0,
	isStart: false,
	arch:    64,
}

type TypeDbg struct {
	pid      int
	path     string
	isAttach bool
	rip      uint64
	isStart  bool
	arch     int
}

var procMapsDetail []*proc

type proc struct {
	start  uint64
	end    uint64
	rwx    string
	offset uint64
	path   string
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
			rwx:    match[3],
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
	}
	cmd := exec.Command(absPath, args...)

	cmd.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Start(); err != nil {
		return nil, err
	}
	dbger.pid = cmd.Process.Pid
	Printf("%s started with PID:%d\n", absPath, dbger.pid)

	_, err = dbger.stopWait()
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
	err := unix.PtraceAttach(pid)
	if err != nil {
		return nil, err
	}

	dbger := &TypeDbg{
		pid:      pid,
		path:     "",
		isAttach: true,
		rip:      0,
		isStart:  true,
	}

	Printf("attached to PID:%d\n", pid)

	_, err = dbger.wait()
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

	err := unix.PtraceDetach(dbger.pid)
	if err != nil {
		return err
	}

	Printf("detached from PID:%d\n", dbger.pid)
	return nil
}

func (dbger *TypeDbg) isStopped() bool {
	path := fmt.Sprintf("/proc/%d/stat", dbger.pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return false
	}

	return fields[2] == "t"
}

func (dbger *TypeDbg) interrupt() error {
	return unix.PtraceInterrupt(dbger.pid)
}

func (dbger *TypeDbg) wait() (unix.WaitStatus, error) {
	var ws unix.WaitStatus
	_, err := unix.Wait4(dbger.pid, &ws, 0, nil)
	if err != nil {
		return 0, err
	}
	if ws.Exited() {
		Printf("PID:%d exited\n", dbger.pid)
		dbger.isStart = false
		return ws, nil
	}
	if ws.Stopped() {
		rip, err := dbger.GetRip()
		rip--
		if err != nil {
			return 0, err
		}
		for i, b := range Bps {
			if b.addr == uintptr(rip) && b.isEnable {
				Printf("stopped at breakpoint %d @ %x\n", i, rip)
				break
			}
		}
	}
	return ws, nil
}

func (dbger *TypeDbg) stopWait() (unix.WaitStatus, error) {
	dbger.stop()
	return dbger.wait()
}

func (dbger *TypeDbg) Continue() error {
	rip, err := dbger.GetRip()
	if err != nil {
		return err
	}
	bp, ok := func(rip uint64) (*TypeBp, bool) {
		rip--
		for i, b := range Bps {
			if b.addr == uintptr(rip) && b.isEnable {
				Printf("stopped at breakpoint %d @ %x\n", i, rip)
				return &b, true
			}
		}
		return nil, false
	}(rip)

	if ok {
		if bp.isEnable {
			if err := bp.disableBp(); err != nil {
				return err
			}
			if err := dbger.SetRip(rip - 1); err != nil {
				return err
			}
			if err := dbger.Step(); err != nil {
				return err
			}
			if _, err = dbger.wait(); err != nil {
				return err
			}
			if err := bp.enableBp(); err != nil {
				return err
			}
		}
	}

	err = unix.PtraceCont(dbger.pid, 0)
	if err != nil {
		return err
	}

	return nil
}

func (dbger *TypeDbg) stop() error {
	ptraceMutex.Lock()
	defer ptraceMutex.Unlock()
	err := unix.Kill(dbger.pid, unix.SIGSTOP)
	return err
}

func (dbger *TypeDbg) Step() error {
	ptraceMutex.Lock()
	defer ptraceMutex.Unlock()
	err := unix.PtraceSingleStep(dbger.pid)
	if err != nil {
		return err
	}
	return nil
}
