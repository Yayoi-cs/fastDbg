package main

import (
	"fmt"
)

func (dbger *TypeDbg) Interactive() {
	for {
		if !dbger.isStart {
			Printf("[fastDbg]$ ")
		} else {
			Printf("[%x]$ ", dbger.rip)
		}

		var req string
		fmt.Scanf("%s", &req)
		if req == "q" || req == "exit" {
			break
		}
		err := dbger.cmdExec(req)
		if err != nil {
			LogError(err.Error())
		}
	}
}
