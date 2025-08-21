package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type Symbol struct {
	Name    string
	Addr    uint64
	Size    uint64
	Type    elf.SymType
	Bind    elf.SymBind
	Section uint16
}

type SymbolTable struct {
	symbols      []Symbol
	addrToSymbol map[uint64]*Symbol
	nameToSymbol map[string]*Symbol
	addrNameMap  map[string]int
	sorted       bool
}

var symTable *SymbolTable

func NewSymbolTable() *SymbolTable {
	return &SymbolTable{
		symbols:      make([]Symbol, 0),
		addrToSymbol: make(map[uint64]*Symbol),
		nameToSymbol: make(map[string]*Symbol),
		addrNameMap:  make(map[string]int),
		sorted:       false,
	}
}

func (st *SymbolTable) AddSymbol(sym Symbol) {
	key := fmt.Sprintf("%x_%s", sym.Addr, sym.Name)

	if existingIdx, exists := st.addrNameMap[key]; exists {
		existing := &st.symbols[existingIdx]

		if sym.Size > existing.Size ||
			(sym.Size == existing.Size && sym.Bind == elf.STB_GLOBAL && existing.Bind == elf.STB_WEAK) {
			st.symbols[existingIdx] = sym
			st.addrToSymbol[sym.Addr] = &st.symbols[existingIdx]
			st.nameToSymbol[sym.Name] = &st.symbols[existingIdx]
		}
		return
	}

	st.symbols = append(st.symbols, sym)
	newIdx := len(st.symbols) - 1
	st.addrToSymbol[sym.Addr] = &st.symbols[newIdx]
	st.nameToSymbol[sym.Name] = &st.symbols[newIdx]
	st.addrNameMap[key] = newIdx
	st.sorted = false
}

func (st *SymbolTable) SortByAddress() {
	if st.sorted {
		return
	}
	sort.Slice(st.symbols, func(i, j int) bool {
		return st.symbols[i].Addr < st.symbols[j].Addr
	})
	st.sorted = true
}

func (dbger *TypeDbg) LoadSymbolsFromELF() error {
	if dbger.path == "" {
		return errors.New("invalid filename")
	}

	file, err := elf.Open(dbger.path)
	if err != nil {
		return err
	}
	defer file.Close()

	symTable = NewSymbolTable()

	if err := loadSymbolSection(file, ".symtab", ".strtab"); err != nil {
		fmt.Printf("failed to load static symbols: %v\n", err)
	}

	if err := loadSymbolSection(file, ".dynsym", ".dynstr"); err != nil {
		fmt.Printf("failed to load dynamic symbols: %v\n", err)
	}

	symTable.SortByAddress()
	Printf("Loaded %d symbols\n", len(symTable.symbols))

	return nil
}

func loadSymbolSection(file *elf.File, symSecName, strSecName string) error {
	var symSection *elf.Section
	for _, section := range file.Sections {
		if section.Name == symSecName {
			symSection = section
			break
		}
	}
	if symSection == nil {
		return fmt.Errorf("symbol section %s not found", symSecName)
	}

	var strSection *elf.Section
	for _, section := range file.Sections {
		if section.Name == strSecName {
			strSection = section
			break
		}
	}
	if strSection == nil {
		return fmt.Errorf("string section %s not found", strSecName)
	}

	_, err := strSection.Data()
	if err != nil {
		return fmt.Errorf("failed to read string table: %v", err)
	}

	symbols, err := file.Symbols()
	if err != nil {
		symbols, err = file.DynamicSymbols()
		if err != nil {
			return fmt.Errorf("failed to read symbols: %v", err)
		}
	}

	for _, sym := range symbols {
		if sym.Name == "" || sym.Value == 0 {
			continue
		}

		if sym.Info&0xf == uint8(elf.STT_FILE) ||
			sym.Info&0xf == uint8(elf.STT_SECTION) {
			continue
		}

		symbol := Symbol{
			Name:    sym.Name,
			Addr:    sym.Value,
			Size:    sym.Size,
			Type:    elf.SymType(sym.Info & 0xf),
			Bind:    elf.SymBind(sym.Info >> 4),
			Section: uint16(sym.Section),
		}

		symTable.AddSymbol(symbol)
	}

	return nil
}

func (dbger *TypeDbg) ResolveAddrToSymbol(addr uint64) (*Symbol, uint64, error) {
	if symTable == nil {
		return nil, 0, errors.New("symbols not loaded")
	}

	if sym, exists := symTable.addrToSymbol[addr]; exists {
		return sym, 0, nil
	}

	symTable.SortByAddress()

	idx := sort.Search(len(symTable.symbols), func(i int) bool {
		return symTable.symbols[i].Addr > addr
	})

	for i := idx - 1; i >= 0; i-- {
		sym := &symTable.symbols[i]
		if sym.Addr <= addr {
			if sym.Size > 0 && addr >= sym.Addr+sym.Size {
				continue
			}
			offset := addr - sym.Addr
			return sym, offset, nil
		}
	}

	return nil, 0, errors.New("no symbol found for address")
}

func (dbger *TypeDbg) ResolveSymbolToAddr(name string) (*Symbol, error) {
	if symTable == nil {
		return nil, errors.New("symbols not loaded")
	}

	if sym, exists := symTable.nameToSymbol[name]; exists {
		return sym, nil
	}

	var matches []*Symbol
	for symName, sym := range symTable.nameToSymbol {
		if strings.Contains(strings.ToLower(symName), strings.ToLower(name)) {
			matches = append(matches, sym)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("symbol '%s' not found", name)
	}

	if len(matches) == 1 {
		return matches[0], nil
	}

	Printf("Multiple symbols found for '%s':\n", name)
	for i, sym := range matches {
		Printf("  %d: %s @ 0x%x\n", i, sym.Name, sym.Addr)
	}

	return matches[0], nil
}

func (dbger *TypeDbg) ListSymbols(filter string) error {
	if symTable == nil {
		return errors.New("symbols not loaded")
	}

	if filter == "" {
		tempFile := fmt.Sprintf("/tmp/fastDbg_%d_%d", os.Getpid(), time.Now().Unix())
		file, err := os.Create(tempFile)
		if err != nil {
			return err
		}

		defer func() {
			file.Close()
			os.Remove(tempFile)
		}()

		symTable.SortByAddress()

		fmt.Fprintf(file, "%-18s %-8s %-8s %s\n", "ADDRESS", "TYPE", "BIND", "NAME")
		fmt.Fprintf(file, "%s\n", strings.Repeat("-", 80))

		count := 0
		for _, sym := range symTable.symbols {
			typeStr := symbolTypeString(sym.Type)
			bindStr := symbolBindString(sym.Bind)
			fmt.Fprintf(file, "0x%016x  %-8s %-8s %s\n", sym.Addr, typeStr, bindStr, sym.Name)
			count++
		}
		file.Close()

		cmd := exec.Command("less", "-S", tempFile)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return err
		}

	} else {
		symTable.SortByAddress()
		count := 0

		Printf("%-18s %-8s %-8s %s\n", "ADDRESS", "TYPE", "BIND", "NAME")
		Printf("%s\n", strings.Repeat("-", 80))

		for _, sym := range symTable.symbols {
			if !strings.Contains(strings.ToLower(sym.Name), strings.ToLower(filter)) {
				continue
			}

			typeStr := symbolTypeString(sym.Type)
			bindStr := symbolBindString(sym.Bind)
			Printf("0x%016x  %-8s %-8s %s\n", sym.Addr, typeStr, bindStr, sym.Name)
			count++
		}

		if count == 0 {
			Printf("No symbols found matching '%s'\n", filter)
		}
	}

	return nil
}

func (dbger *TypeDbg) GetSymbolInfo(name string) error {
	sym, err := dbger.ResolveSymbolToAddr(name)
	if err != nil {
		return err
	}

	Printf("Symbol: %s\n", sym.Name)
	Printf("Address: 0x%016x\n", sym.Addr)
	Printf("Size: %d bytes\n", sym.Size)
	Printf("Type: %s\n", symbolTypeString(sym.Type))
	Printf("Bind: %s\n", symbolBindString(sym.Bind))
	Printf("Section: %d\n", sym.Section)

	return nil
}

func symbolTypeString(t elf.SymType) string {
	switch t {
	case elf.STT_NOTYPE:
		return "NOTYPE"
	case elf.STT_OBJECT:
		return "OBJECT"
	case elf.STT_FUNC:
		return "FUNC"
	case elf.STT_SECTION:
		return "SECTION"
	case elf.STT_FILE:
		return "FILE"
	case elf.STT_COMMON:
		return "COMMON"
	case elf.STT_TLS:
		return "TLS"
	default:
		return "UNKNOWN"
	}
}

func symbolBindString(b elf.SymBind) string {
	switch b {
	case elf.STB_LOCAL:
		return "LOCAL"
	case elf.STB_GLOBAL:
		return "GLOBAL"
	case elf.STB_WEAK:
		return "WEAK"
	default:
		return "UNKNOWN"
	}
}

func (dbger *TypeDbg) resolveSyms(addr uint64) {
	sym, offset, err := dbger.ResolveAddrToSymbol(addr)
	if err != nil {
		Printf("0x%016x: <no symbol>\n", addr)
		return
	}

	if offset == 0 {
		Printf("0x%016x: %s\n", addr, sym.Name)
	} else {
		Printf("0x%016x: %s+0x%x\n", addr, sym.Name, offset)
	}
}
