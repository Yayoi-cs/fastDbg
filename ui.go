package main

import (
	"fmt"
)

func (dbger *TypeDbg) Interactive() {
	if dbger.rip != 0 {
		Printf("[%x]$ ", dbger.rip)
	} else {
		Printf("[fastDbg]$ ")
	}

	var req string
	fmt.Scanf("%s", &req)

	err := dbger.cmdExec(req)
	if err != nil {
		LogError(err.Error())
	}
}
