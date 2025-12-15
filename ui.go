package main

import (
	"fastDbg/ebpf"
	"fmt"
	"github.com/chzyer/readline"
	"io"
	"strings"
)

func (dbger *TypeDbg) resolveSymbols(cmd string) (string, error) {
	return dbger.resolveSymbolsNew(cmd)
}

func (dbger *TypeDbg) Interactive(doContext bool) {
	if err := dbger.LoadSymbolsFromELF(); err != nil {
		LogError("Failed to load symbols: %v", err)
	}

	if dbger.isStart && dbger.isProcessAlive() {
		if err := dbger.Reload(); err != nil {
			LogError("Failed to reload symbols: %v", err)
		}
	}

	prev := ""

	rl, err := readline.NewEx(&readline.Config{
		Prompt:              "[fastDbg]$ ",
		HistoryFile:         "/tmp/fastdbg_history.txt",
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})
	if err != nil {
		panic(err)
	}
	defer rl.Close()

	if doContext {
		dbger.cmdContext(nil)
	}

	for {
		if ebpf.MapFlag {
			dbger.loadBase()
			ebpf.MapFlag = false
		}
		if !dbger.isStart {
			rl.SetPrompt("[fastDbg]$ ")
		} else {
			rl.SetPrompt(fmt.Sprintf("[%sfastDbg%s:%s0x%x%s]$ ", ColorCyan, ColorReset, ColorCyan, dbger.rip, ColorReset))
		}

		req, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt || err == io.EOF {
				break
			}
			continue
		}

		if req == "" {
			if prev == "" {
				continue
			}
			req = prev
		}

		if req == "q" || req == "exit" {
			break
		}

		prev = req

		resolvedReq := req
		if strings.Contains(req, "$") {
			var resolveErr error
			resolvedReq, resolveErr = dbger.resolveSymbols(req)
			if resolveErr != nil {
				LogError("Failed to resolve symbols in command: %v", resolveErr)
				LogError("Attempting to execute command anyway...")
			}
		}

		err = dbger.cmdExec(resolvedReq)

		if err != nil {
			LogError(err.Error())
		}
	}
}

func filterInput(r rune) (rune, bool) {
	switch r {
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}
