package main

import (
	"fastDbg/ebpf"
	"fmt"
	"github.com/chzyer/readline"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func (dbger *TypeDbg) resolveSymbols(cmd string) (string, error) {
	return dbger.resolveSymbolsNew(cmd)
}

var interruptFlag = make(chan struct{}, 1)

func (dbger *TypeDbg) Interactive(doContext bool) {
	if err := dbger.LoadSymbolsFromELF(); err != nil {
		LogError("Failed to load symbols: %v", err)
	}

	if dbger.isStart && dbger.isProcessAlive() {
		if err := dbger.Reload(); err != nil {
			LogError("Failed to reload symbols: %v", err)
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	defer signal.Stop(sigChan)

	go func() {
		for range sigChan {
			if dbger.isStart && dbger.isProcessAlive() && !dbger.isStopped() {
				if err := syscall.Kill(dbger.pid, syscall.SIGSTOP); err != nil {
					LogError("Failed to send SIGSTOP to process: %v", err)
					continue
				}
				select {
				case interruptFlag <- struct{}{}:
				default:
				}
			}
		}
	}()

	prev := ""

	rl, err := readline.NewEx(&readline.Config{
		Prompt:                 "[fastDbg]$ ",
		HistoryFile:            "/tmp/fastdbg_history.txt",
		InterruptPrompt:        "",
		EOFPrompt:              "exit",
		HistorySearchFold:      true,
		FuncFilterInputRune:    filterInput,
		DisableAutoSaveHistory: false,
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
			if err == readline.ErrInterrupt {
				if dbger.isStart && dbger.isProcessAlive() {
					if !dbger.isStopped() {
						if err := dbger.interrupt(); err != nil {
							LogError("Failed to interrupt process: %v", err)
						} else {
							if _, waitErr := dbger.wait(); waitErr != nil {
								LogError("Failed to wait after interrupt: %v", waitErr)
							} else {
								if rip, ripErr := dbger.GetRip(); ripErr == nil {
									dbger.rip = rip
								}
								dbger.cmdContext(nil)
							}
						}
					}
				}
				continue
			}
			if err == io.EOF {
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
