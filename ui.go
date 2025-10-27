package main

import (
	"fmt"
	"github.com/chzyer/readline"
	"io"
	"regexp"
	"strings"
)

// resolveSymbols replaces $<symbol> patterns with their resolved addresses
func (dbger *TypeDbg) resolveSymbols(cmd string) (string, error) {
	// Pattern to match $<symbol_name>
	// Symbol names can contain alphanumeric characters, underscores, dots, and @
	symPattern := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_@.+-]*)`)

	var resolveErr error
	result := symPattern.ReplaceAllStringFunc(cmd, func(match string) string {
		// Extract symbol name (remove the $ prefix)
		symName := strings.TrimPrefix(match, "$")

		// Skip register names (these start with $ in x86_64 syntax)
		registerNames := []string{
			"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
			"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
			"rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
			"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
			"ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
			"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
		}
		for _, reg := range registerNames {
			if strings.EqualFold(symName, reg) {
				return match // Keep register references as-is
			}
		}

		// Resolve the symbol to an address
		sym, err := dbger.ResolveSymbolToAddr(symName)
		if err != nil {
			resolveErr = err
			LogError("Failed to resolve symbol '%s': %v", symName, err)
			return match // Keep original if resolution fails
		}

		// Calculate actual address
		actualAddr := sym.Addr
		if sym.LibIndex < len(libRoots) {
			actualAddr += libRoots[sym.LibIndex].base
		}

		// Return the address in hex format
		return fmt.Sprintf("0x%x", actualAddr)
	})

	return result, resolveErr
}

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

		// Resolve $<symbol> patterns to addresses
		resolvedReq := req
		if strings.Contains(req, "$") {
			resolvedReq, _ = dbger.resolveSymbols(req)
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
