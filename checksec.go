package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

type checksecResult struct {
	Path     string
	Type     string
	IsExec   bool
	PIE      bool
	Canary   bool
	NX       bool
	NXKnown  bool
	RELRO    string
	Fortify  bool
	RWX      []string
	Stripped bool
}

func runChecksec(path string) (*checksecResult, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := &checksecResult{Path: path, Type: f.Type.String()}

	hasInterp := false
	for _, ph := range f.Progs {
		if ph.Type == elf.PT_INTERP {
			hasInterp = true
			break
		}
	}
	res.IsExec = f.Type == elf.ET_EXEC || (f.Type == elf.ET_DYN && hasInterp)
	res.PIE = f.Type == elf.ET_DYN

	syms, _ := f.DynamicSymbols()
	if len(syms) == 0 {
		syms, _ = f.Symbols()
	}
	for _, s := range syms {
		switch {
		case s.Name == "__stack_chk_fail" || s.Name == "__stack_chk_fail_local":
			res.Canary = true
		case strings.HasPrefix(s.Name, "__") && strings.HasSuffix(s.Name, "_chk"):
			res.Fortify = true
		}
	}

	res.Stripped = f.Section(".symtab") == nil

	for _, ph := range f.Progs {
		if ph.Type == elf.PT_GNU_STACK {
			res.NXKnown = true
			res.NX = ph.Flags&elf.PF_X == 0
			break
		}
	}

	for _, ph := range f.Progs {
		if ph.Type == elf.PT_LOAD &&
			ph.Flags&elf.PF_W != 0 && ph.Flags&elf.PF_X != 0 {
			res.RWX = append(res.RWX,
				fmt.Sprintf("0x%x-0x%x", ph.Vaddr, ph.Vaddr+ph.Memsz))
		}
	}

	hasRelro := false
	for _, ph := range f.Progs {
		if ph.Type == elf.PT_GNU_RELRO {
			hasRelro = true
			break
		}
	}
	bindNow := false
	if vals, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
		bindNow = true
	}
	if !bindNow {
		if vals, err := f.DynValue(elf.DT_FLAGS); err == nil {
			for _, v := range vals {
				if v&uint64(elf.DF_BIND_NOW) != 0 {
					bindNow = true
					break
				}
			}
		}
	}
	if !bindNow {
		if vals, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
			for _, v := range vals {
				if v&0x1 != 0 {
					bindNow = true
					break
				}
			}
		}
	}
	switch {
	case !hasRelro:
		res.RELRO = "None"
	case bindNow:
		res.RELRO = "Full"
	default:
		res.RELRO = "Partial"
	}

	return res, nil
}

func printChecksecOne(r *checksecResult) {
	enabledColor := func(b bool) string {
		if b {
			return ColorGreen + "Enabled" + ColorReset
		}
		return ColorRed + "Disabled" + ColorReset
	}

	fmt.Printf("File       : %s%s%s\n", ColorCyan, r.Path, ColorReset)
	fmt.Printf("Type       : %s%s%s\n", ColorCyan, r.Type, ColorReset)
	fmt.Println()
	fmt.Println("Mitigations:")
	fmt.Printf("  PIE      : %s\n", enabledColor(r.PIE))
	fmt.Printf("  Canary   : %s\n", enabledColor(r.Canary))

	if r.NXKnown {
		fmt.Printf("  NX       : %s\n", enabledColor(r.NX))
	} else {
		fmt.Printf("  NX       : %sUnknown%s (no PT_GNU_STACK; kernel default applies)\n", ColorYellow, ColorReset)
	}

	relroColor := ColorRed
	switch r.RELRO {
	case "Partial":
		relroColor = ColorYellow
	case "Full":
		relroColor = ColorGreen
	}
	fmt.Printf("  RELRO    : %s%s%s\n", relroColor, r.RELRO, ColorReset)

	fmt.Printf("  Fortify  : %s\n", enabledColor(r.Fortify))

	if len(r.RWX) == 0 {
		fmt.Printf("  RWX      : %sNone%s\n", ColorGreen, ColorReset)
	} else {
		fmt.Printf("  RWX      : %sYes%s (%s)\n", ColorRed, ColorReset, strings.Join(r.RWX, ", "))
	}

	if r.Stripped {
		fmt.Printf("  Stripped : %sYes%s (no .symtab)\n", ColorYellow, ColorReset)
	} else {
		fmt.Printf("  Stripped : %sNo%s (.symtab present)\n", ColorGreen, ColorReset)
	}
}

func printChecksecTable(results []*checksecResult) {
	mark := func(b bool, good bool) string {
		if b == good {
			return ColorGreen + "o" + ColorReset
		}
		return ColorRed + "x" + ColorReset
	}
	relroCell := func(s string) string {
		switch s {
		case "Full":
			return ColorGreen + s + ColorReset + strings.Repeat(" ", 8-len(s))
		case "Partial":
			return ColorYellow + s + ColorReset + strings.Repeat(" ", 8-len(s))
		default:
			return ColorRed + s + ColorReset + strings.Repeat(" ", 8-len(s))
		}
	}

	fmt.Printf("%s%-30s %-3s %-6s %-3s %-14s %-7s %-3s %-8s%s\n", ColorBold, "LIBRARY", "PIE", "CANARY", "NX", "RELRO", "FORTIFY", "RWX", "STRIPPED", ColorReset)
	for _, r := range results {
		nx := mark(r.NX, true)
		if !r.NXKnown {
			nx = ColorYellow + "?" + ColorReset
		}
		rwx := ColorGreen + "-" + ColorReset
		if len(r.RWX) > 0 {
			rwx = ColorRed + "Y" + ColorReset
		}
		stripped := ColorGreen + "-" + ColorReset
		if r.Stripped {
			stripped = ColorYellow + "Y" + ColorReset
		}
		fmt.Printf("%-30s %s   %s      %s   %s       %s       %s   %s\n", truncate(filepath.Base(r.Path), 30), mark(r.PIE, true), mark(r.Canary, true), nx, relroCell(r.RELRO), mark(r.Fortify, true), rwx, stripped)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func (dbger *TypeDbg) cmdCheckSec(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	arg := ""
	if len(args) > 2 {
		arg = strings.TrimSpace(args[2])
	}

	if arg == "" {
		if dbger.path == "" {
			return errors.New("no main binary path set")
		}
		hLine("checksec")
		r, err := runChecksec(dbger.path)
		if err != nil {
			return err
		}
		printChecksecOne(r)
		hLineRaw()
		return nil
	}

	if strings.EqualFold(arg, "all") {
		if len(libRoots) == 0 {
			return errors.New("no libraries loaded")
		}
		results := make([]*checksecResult, 0, len(libRoots))
		for _, lr := range libRoots {
			if lr.name == "" {
				continue
			}
			r, err := runChecksec(lr.name)
			if err != nil {
				results = append(results, &checksecResult{Path: lr.name, Type: fmt.Sprintf("<error: %v>", err)})
				continue
			}
			results = append(results, r)
		}
		hLine("checksec (all libraries)")
		printChecksecTable(results)
		hLineRaw()
		return nil
	}

	for _, lr := range libRoots {
		if lr.name == "" {
			continue
		}
		base := filepath.Base(lr.name)
		if strings.Contains(strings.ToLower(base), strings.ToLower(arg)) ||
			strings.Contains(strings.ToLower(lr.name), strings.ToLower(arg)) {
			hLine("checksec")
			r, err := runChecksec(lr.name)
			if err != nil {
				return err
			}
			printChecksecOne(r)
			hLineRaw()
			return nil
		}
	}
	return fmt.Errorf("no loaded library matches %q", arg)
}
