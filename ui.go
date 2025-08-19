package main

import (
	"bufio"
	"os"
)

func (dbger *TypeDbg) Interactive() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		if !dbger.isStart {
			Printf("[fastDbg]$ ")
		} else {
			Printf("[%x]$ ", dbger.rip)
		}

		var req string
		if !scanner.Scan() {
			break
		}
		req = scanner.Text()
		if req == "" {
			continue
		}
		if req == "q" || req == "exit" {
			break
		}
		err := dbger.cmdExec(req)
		if err != nil {
			LogError(err.Error())
		}
	}
}
