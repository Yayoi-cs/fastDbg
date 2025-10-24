package main

import (
	"fmt"
	"github.com/chzyer/readline"
	"io"
)

func (dbger *TypeDbg) Interactive() {
	dbger.LoadSymbolsFromELF()
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

	for {
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
		err = dbger.cmdExec(req)

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
