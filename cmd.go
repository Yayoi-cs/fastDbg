package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

var cmd = map[string]func(*TypeDbg, interface{}) error{
	"^\\s*(b|break)\\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$": (*TypeDbg).cmdBreak,
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
	_, err = NewBp(uintptr(addr), dbger.pid)

	return err
}
