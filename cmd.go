package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

var cmd = map[string]func(*TypeDbg, interface{}) error{
	"^\\s*(b|break|B|BREAK)\\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$": (*TypeDbg).cmdBreak,
	"^\\s*(run|RUN)(?:\\s+(.+))?$":                                         (*TypeDbg).cmdRun,
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
	fmt.Println("Log args @ cmdBreak ", args)
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	if !dbger.isStart {
		tmpBps = append(tmpBps, uintptr(addr))
		Printf("booked breakpoint %d @ %x\n", len(tmpBps), addr)
		return nil
	}

	_, err = NewBp(uintptr(addr), dbger.pid)

	return err
}

func (dbger *TypeDbg) cmdRun(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	fmt.Println("Log args @ cmdBreak ", args)
	tmpDbger, err := Run(dbger.path, args...)
	if err != nil {
		return err
	}
	mainDbger = *tmpDbger

	for _, addr := range tmpBps {
		_, err = NewBp(addr, dbger.pid)
		if err != nil {
			return err
		}
	}
	tmpBps = []uintptr{}

	return nil
}
