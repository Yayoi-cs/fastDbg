package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var mainDbger TypeDbg = TypeDbg{
	pid:      0,
	path:     "",
	isAttach: false,
	rip:      0,
	isStart:  false,
}

type TypeDbg struct {
	pid      int
	path     string
	isAttach bool
	rip      uint64
	isStart  bool
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
	dbger := &TypeDbg{
		pid:      -1,
		path:     absPath,
		isAttach: false,
		rip:      0,
		isStart:  true,
	}
	cmd := exec.Command(absPath, args...)

	cmd.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}

	if err = cmd.Start(); err != nil {
		return nil, err
	}
	dbger.pid = cmd.Process.Pid
	Printf("%s started with PID:%d\n", absPath, dbger.pid)

	_, err = dbger.wait()
	if err != nil {
		return nil, err
	}

	dbger.rip, err = dbger.GetRip()

	if err != nil {
		return nil, err
	}

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
	}

	Printf("attached to PID:%d\n", pid)

	_, err = dbger.wait()
	if err != nil {
		return nil, err
	}

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

func (dbger *TypeDbg) wait() (unix.WaitStatus, error) {
	var ws unix.WaitStatus
	_, err := unix.Wait4(dbger.pid, &ws, unix.WCONTINUED, nil)
	if err != nil {
		return 0, err
	}
	if ws.Exited() {
		return 0, errors.New("already exited")
	}
	if ws.Stopped() {
		rip, err := dbger.GetRip()
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

func (dbger *TypeDbg) Wait() (unix.WaitStatus, error) {
	return dbger.wait()
}

func (dbger *TypeDbg) Continue() error {
	rip, err := dbger.GetRip()
	if err != nil {
		return err
	}

	bp, ok := func(rip uint64) (*TypeBp, bool) {
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

func (dbger *TypeDbg) Step() error {
	err := unix.PtraceSingleStep(dbger.pid)
	if err != nil {
		return err
	}
	return nil
}
