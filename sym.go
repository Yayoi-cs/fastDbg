package main

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type LibraryRange struct {
	libIndex int
	start    uint64
	end      uint64
}

type rootStruct struct {
	name string
	base uint64
	end  uint64
	root *symTree
}

type symTree struct {
	str *string
	p   map[uint8]*symTree
}

type PLTEntry struct {
	Address      uint64
	Name         string
	OriginalName string
	Offset       uint64
	AddEnd       int64
	IsSynthetic  bool
}

type GOTEntry struct {
	Address uint64
	Name    string
	Value   uint64
}

type ELFSymbol struct {
	NameOffset uint32
	Info       uint8
	Other      uint8
	Section    elf.SectionIndex
	Value      uint64
	Size       uint64
}

type Relocation struct {
	Offset      uint64
	Info        uint64
	SymbolIndex uint32
	Type        uint32
	Addend      int64
}

var libRoots []rootStruct
var libraryRanges []LibraryRange

func addTreeToLib(libIndex int, ptr uint64, name *string) {
	if libIndex >= len(libRoots) {
		return
	}

	symTmp := libRoots[libIndex].root
	if symTmp == nil {
		libRoots[libIndex].root = &symTree{p: make(map[uint8]*symTree)}
		symTmp = libRoots[libIndex].root
	}

	for i := 64 - 8; i > 0; i -= 8 {
		key := uint8((ptr >> i) & 0xff)
		v, ok := symTmp.p[key]
		if !ok {
			newNode := symTree{p: make(map[uint8]*symTree)}
			symTmp.p[key] = &newNode
			symTmp = &newNode
		} else {
			symTmp = v
		}
	}

	lastKey := uint8(ptr & 0xff)
	if symTmp.p[lastKey] == nil {
		symTmp.p[lastKey] = &symTree{p: make(map[uint8]*symTree)}
	}
	symTmp.p[lastKey].str = name
}

func addr2NameFromLibExact(libIndex int, ptr uint64) (*string, error) {
	if libIndex >= len(libRoots) || libRoots[libIndex].root == nil {
		return nil, errors.New("library not found")
	}

	symTmp := libRoots[libIndex].root

	for i := 64 - 8; i > 0; i -= 8 {
		key := uint8((ptr >> i) & 0xff)
		v, ok := symTmp.p[key]
		if !ok {
			return nil, errors.New("symbol not found")
		}
		symTmp = v
	}

	lastKey := uint8(ptr & 0xff)
	finalNode, ok := symTmp.p[lastKey]
	if !ok || finalNode == nil || finalNode.str == nil {
		return nil, errors.New("symbol not found")
	}

	return finalNode.str, nil
}

func findNearestSymbolInLib(libIndex int, relativeAddr uint64) (*string, uint64) {
	if libIndex >= len(libRoots) || symTable == nil {
		return nil, 0
	}

	var bestSymbol *string
	var bestOffset uint64 = ^uint64(0)

	for _, sym := range symTable.symbols {
		if sym.LibIndex != libIndex {
			continue
		}

		if sym.Addr <= relativeAddr {
			offset := relativeAddr - sym.Addr
			if sym.Size > 0 && offset >= sym.Size {
				continue
			}
			if offset < bestOffset {
				bestOffset = offset
				bestSymbol = &sym.Name
			}
		}
	}

	if bestSymbol != nil {
		return bestSymbol, bestOffset
	}
	return nil, 0
}

func findLibraryForAddress(addr uint64) int {
	idx := sort.Search(len(libraryRanges), func(i int) bool {
		return libraryRanges[i].end > addr
	})

	for i := idx; i < len(libraryRanges); i++ {
		r := &libraryRanges[i]
		if addr >= r.start && addr < r.end {
			return r.libIndex
		}
	}

	for i := range libRoots {
		if libRoots[i].base > 0 {
			if addr >= libRoots[i].base && (libRoots[i].end == 0 || addr < libRoots[i].end) {
				return i
			}
		} else if i == 0 {
			return 0
		}
	}
	return -1
}

func addr2Name(addr uint64) (*string, uint64, error) {
	libIndex := findLibraryForAddress(addr)
	if libIndex < 0 {
		return nil, 0, errors.New("address not found in any library")
	}

	relativeAddr := addr
	if libRoots[libIndex].base > 0 {
		if addr >= libRoots[libIndex].base {
			relativeAddr = addr - libRoots[libIndex].base
		} else {
			return nil, 0, errors.New("address out of library range")
		}
	}

	if namePtr, err := addr2NameFromLibExact(libIndex, relativeAddr); err == nil && namePtr != nil {
		return namePtr, 0, nil
	}

	bestSymbol, bestOffset := findNearestSymbolInLib(libIndex, relativeAddr)
	if bestSymbol != nil {
		return bestSymbol, bestOffset, nil
	}

	return nil, 0, errors.New("symbol not found")
}

type Symbol struct {
	Name     string
	Addr     uint64
	Size     uint64
	Type     elf.SymType
	Bind     elf.SymBind
	Section  uint16
	LibIndex int
}

type SymbolTable struct {
	symbols      []Symbol
	addrToSymbol map[uint64]*Symbol
	nameToSymbol map[string]*Symbol
	addrNameMap  map[string]int
	rangeMap     map[uint64]*Symbol
	rangeDirty   bool
	sortedAddrs  []uint64
}

var symTable *SymbolTable

func NewSymbolTable() *SymbolTable {
	return &SymbolTable{
		symbols:      make([]Symbol, 0),
		addrToSymbol: make(map[uint64]*Symbol),
		nameToSymbol: make(map[string]*Symbol),
		addrNameMap:  make(map[string]int),
		rangeMap:     make(map[uint64]*Symbol),
		rangeDirty:   false,
		sortedAddrs:  nil,
	}
}

func (st *SymbolTable) AddSymbol(sym Symbol) {
	key := fmt.Sprintf("%x_%s_%d", sym.Addr, sym.Name, sym.LibIndex)

	actualAddr := sym.Addr
	if sym.LibIndex < len(libRoots) {
		actualAddr += libRoots[sym.LibIndex].base
	}

	if existingIdx, exists := st.addrNameMap[key]; exists {
		existing := &st.symbols[existingIdx]

		if sym.Size > existing.Size ||
			(sym.Size == existing.Size && sym.Bind == elf.STB_GLOBAL && existing.Bind == elf.STB_WEAK) {
			oldActualAddr := existing.Addr
			if existing.LibIndex < len(libRoots) {
				oldActualAddr += libRoots[existing.LibIndex].base
			}
			delete(st.rangeMap, oldActualAddr)
			delete(st.addrToSymbol, oldActualAddr)

			st.symbols[existingIdx] = sym
			st.addrToSymbol[actualAddr] = &st.symbols[existingIdx]
			st.nameToSymbol[sym.Name] = &st.symbols[existingIdx]
			st.rangeMap[actualAddr] = &st.symbols[existingIdx]
			st.rangeDirty = true

			addTreeToLib(sym.LibIndex, sym.Addr, &st.symbols[existingIdx].Name)
		}
		return
	}

	st.symbols = append(st.symbols, sym)
	newIdx := len(st.symbols) - 1

	st.addrToSymbol[actualAddr] = &st.symbols[newIdx]
	st.nameToSymbol[sym.Name] = &st.symbols[newIdx]
	st.addrNameMap[key] = newIdx
	st.rangeMap[actualAddr] = &st.symbols[newIdx]
	st.rangeDirty = true

	addTreeToLib(sym.LibIndex, sym.Addr, &st.symbols[newIdx].Name)
}

func (st *SymbolTable) getSortedAddresses() []uint64 {
	if !st.rangeDirty && st.sortedAddrs != nil {
		return st.sortedAddrs
	}

	st.sortedAddrs = st.sortedAddrs[:0]

	if cap(st.sortedAddrs) < len(st.rangeMap) {
		st.sortedAddrs = make([]uint64, 0, len(st.rangeMap))
	}

	for addr := range st.rangeMap {
		st.sortedAddrs = append(st.sortedAddrs, addr)
	}

	sort.Slice(st.sortedAddrs, func(i, j int) bool {
		return st.sortedAddrs[i] < st.sortedAddrs[j]
	})

	st.rangeDirty = false
	return st.sortedAddrs
}

func (dbger *TypeDbg) ldd() ([]string, error) {
	var lib []string
	out, err := exec.Command("ldd", dbger.path).Output()
	if err != nil {
		return nil, err
	}
	for i, f := range strings.Fields(string(out)) {
		if strings.HasPrefix(f, "(") {
			tmp := strings.Fields(string(out))[i-1]
			if strings.Contains(tmp, "/") {
				resolved, err := filepath.EvalSymlinks(tmp)
				if err != nil {
					tmp, _ = filepath.Abs(tmp)
				} else {
					tmp, _ = filepath.Abs(resolved)
				}
				lib = append(lib, tmp)
			}
		}
	}
	return lib, nil
}

func (dbger *TypeDbg) isPIE() (bool, error) {
	file, err := elf.Open(dbger.path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	return file.Type == elf.ET_DYN, nil
}

func (dbger *TypeDbg) getBaseAddress(pid int, libPath string) (uint64, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, libPath) {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				addrRange := strings.Split(fields[0], "-")
				if len(addrRange) == 2 {
					baseAddr, err := strconv.ParseUint(addrRange[0], 16, 64)
					if err == nil {
						return baseAddr, nil
					}
				}
			}
		}
	}
	return 0, errors.New("base address not found")
}

func calculateLibraryEnd(libIndex int) uint64 {
	if libIndex >= len(libRoots) || symTable == nil {
		return 0
	}

	maxAddr := libRoots[libIndex].base
	for _, sym := range symTable.symbols {
		if sym.LibIndex != libIndex {
			continue
		}
		actualAddr := sym.Addr + libRoots[libIndex].base
		endAddr := actualAddr + sym.Size
		if endAddr > maxAddr {
			maxAddr = endAddr
		}
	}

	if maxAddr-libRoots[libIndex].base < 65536 {
		maxAddr = libRoots[libIndex].base + 65536
	}

	return maxAddr
}

func buildLibraryRanges() {
	libraryRanges = libraryRanges[:0]

	for i := range libRoots {
		end := calculateLibraryEnd(i)
		libRoots[i].end = end

		libraryRanges = append(libraryRanges, LibraryRange{
			libIndex: i,
			start:    libRoots[i].base,
			end:      end,
		})
	}

	sort.Slice(libraryRanges, func(i, j int) bool {
		return libraryRanges[i].start < libraryRanges[j].start
	})
}

func getByteOrder(file *elf.File) binary.ByteOrder {
	if file.Data == elf.ELFDATA2LSB {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func parseSymbol(data []byte, file *elf.File) ELFSymbol {
	var symbol ELFSymbol
	byteOrder := getByteOrder(file)

	if file.Class == elf.ELFCLASS64 {
		symbol.NameOffset = byteOrder.Uint32(data[0:4])
		symbol.Info = data[4]
		symbol.Other = data[5]
		symbol.Section = elf.SectionIndex(byteOrder.Uint16(data[6:8]))
		symbol.Value = byteOrder.Uint64(data[8:16])
		symbol.Size = byteOrder.Uint64(data[16:24])
	} else {
		symbol.NameOffset = byteOrder.Uint32(data[0:4])
		symbol.Value = uint64(byteOrder.Uint32(data[4:8]))
		symbol.Size = uint64(byteOrder.Uint32(data[8:12]))
		symbol.Info = data[12]
		symbol.Other = data[13]
		symbol.Section = elf.SectionIndex(byteOrder.Uint16(data[14:16]))
	}

	return symbol
}

func getSymbolName(nameOffset uint32, dynStrings []byte) string {
	if nameOffset >= uint32(len(dynStrings)) {
		return ""
	}

	end := nameOffset
	for end < uint32(len(dynStrings)) && dynStrings[end] != 0 {
		end++
	}

	return string(dynStrings[nameOffset:end])
}

func parseRelocations(section *elf.Section, file *elf.File) ([]Relocation, error) {
	data, err := section.Data()
	if err != nil {
		return nil, err
	}

	var relocations []Relocation
	var entrySize int

	if section.Type == elf.SHT_RELA {
		if file.Class == elf.ELFCLASS64 {
			entrySize = 24
		} else {
			entrySize = 12
		}
	} else if section.Type == elf.SHT_REL {
		if file.Class == elf.ELFCLASS64 {
			entrySize = 16
		} else {
			entrySize = 8
		}
	}

	entryCount := len(data) / entrySize
	byteOrder := getByteOrder(file)

	for i := 0; i < entryCount; i++ {
		entryData := data[i*entrySize : (i+1)*entrySize]
		var reloc Relocation

		if file.Class == elf.ELFCLASS64 {
			reloc.Offset = byteOrder.Uint64(entryData[0:8])
			reloc.Info = byteOrder.Uint64(entryData[8:16])
			reloc.SymbolIndex = uint32(reloc.Info >> 32)
			reloc.Type = uint32(reloc.Info & 0xffffffff)

			if section.Type == elf.SHT_RELA && len(entryData) >= 24 {
				reloc.Addend = int64(byteOrder.Uint64(entryData[16:24]))
			}
		} else {
			reloc.Offset = uint64(byteOrder.Uint32(entryData[0:4]))
			reloc.Info = uint64(byteOrder.Uint32(entryData[4:8]))
			reloc.SymbolIndex = uint32(reloc.Info >> 8)
			reloc.Type = uint32(reloc.Info & 0xff)

			if section.Type == elf.SHT_RELA && len(entryData) >= 12 {
				reloc.Addend = int64(int32(byteOrder.Uint32(entryData[8:12])))
			}
		}

		relocations = append(relocations, reloc)
	}

	return relocations, nil
}

func getPLTEntrySize(machine elf.Machine) int {
	switch machine {
	case elf.EM_X86_64:
		return 16
	case elf.EM_386:
		return 16
	case elf.EM_AARCH64:
		return 16
	case elf.EM_ARM:
		return 12
	default:
		return 16
	}
}

func loadDynamicSymbols(file *elf.File) ([]ELFSymbol, []byte, error) {
	dynsymSection := file.Section(".dynsym")
	if dynsymSection == nil {
		return nil, nil, fmt.Errorf(".dynsym section not found")
	}

	dynstrSection := file.Section(".dynstr")
	if dynstrSection == nil {
		return nil, nil, fmt.Errorf(".dynstr section not found")
	}

	dynstrData, err := dynstrSection.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read .dynstr: %w", err)
	}

	dynsymData, err := dynsymSection.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read .dynsym: %w", err)
	}

	var symbolSize int
	if file.Class == elf.ELFCLASS64 {
		symbolSize = 24
	} else {
		symbolSize = 16
	}

	symbolCount := len(dynsymData) / symbolSize
	dynSymbols := make([]ELFSymbol, symbolCount)

	for i := 0; i < symbolCount; i++ {
		symbolData := dynsymData[i*symbolSize : (i+1)*symbolSize]
		symbol := parseSymbol(symbolData, file)
		dynSymbols[i] = symbol
	}

	return dynSymbols, dynstrData, nil
}

func (dbger *TypeDbg) analyzePLTGOT(filename string) error {
	file, err := elf.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	dynSymbols, dynStrings, err := loadDynamicSymbols(file)
	if err != nil {
		return err
	}

	pltSection := file.Section(".plt.sec")
	if pltSection == nil {
		pltSection = file.Section(".plt")
	}

	if pltSection != nil {
		relPltSection := file.Section(".rela.plt")
		if relPltSection == nil {
			relPltSection = file.Section(".rel.plt")
		}

		if relPltSection != nil {
			relocations, err := parseRelocations(relPltSection, file)
			if err == nil {
				pltEntrySize := getPLTEntrySize(file.Machine)
				isModernPLT := (pltSection.Name == ".plt.sec")

				for i, reloc := range relocations {
					if reloc.SymbolIndex >= uint32(len(dynSymbols)) {
						continue
					}

					var pltEntryAddr uint64
					if isModernPLT {
						pltEntryAddr = pltSection.Addr + uint64(i*pltEntrySize)
					} else {
						pltEntryAddr = pltSection.Addr + uint64((i+1)*pltEntrySize)
					}

					symbol := dynSymbols[reloc.SymbolIndex]
					symbolName := getSymbolName(symbol.NameOffset, dynStrings)
					if symbolName == "" {
						continue
					}

					pltName := symbolName + "@plt"
					if reloc.Addend != 0 {
						pltName += fmt.Sprintf("+0x%x", reloc.Addend)
					}

					pltSym := Symbol{
						Name:     pltName,
						Addr:     pltEntryAddr - libRoots[0].base,
						Size:     uint64(pltEntrySize),
						Type:     elf.STT_FUNC,
						Bind:     elf.STB_GLOBAL,
						Section:  0,
						LibIndex: 0,
					}
					symTable.AddSymbol(pltSym)
				}
			}
		}
	}

	gotSection := file.Section(".got.plt")
	if gotSection == nil {
		gotSection = file.Section(".got")
	}

	if gotSection != nil {
		gotData, err := gotSection.Data()
		if err == nil {
			var entrySize int
			if file.Class == elf.ELFCLASS64 {
				entrySize = 8
			} else {
				entrySize = 4
			}

			entryCount := len(gotData) / entrySize
			for i := 0; i < entryCount; i++ {
				gotAddr := gotSection.Addr + uint64(i*entrySize)
				gotName := fmt.Sprintf("GOT[%d]", i)

				gotSym := Symbol{
					Name:     gotName,
					Addr:     gotAddr - libRoots[0].base,
					Size:     uint64(entrySize),
					Type:     elf.STT_OBJECT,
					Bind:     elf.STB_GLOBAL,
					Section:  0,
					LibIndex: 0,
				}
				symTable.AddSymbol(gotSym)
			}
		}
	}

	return nil
}

func (dbger *TypeDbg) LoadSymbolsFromELF() error {
	if dbger.path == "" {
		return errors.New("invalid filename")
	}

	symTable = NewSymbolTable()
	libRoots = make([]rootStruct, 0)

	isPie, err := dbger.isPIE()
	if err != nil {
		return err
	}

	mainRoot := rootStruct{
		name: dbger.path,
		base: 0,
		end:  0,
		root: &symTree{p: make(map[uint8]*symTree)},
	}

	if isPie {
		mainRoot.base = 0
	}

	libRoots = append(libRoots, mainRoot)

	if err := dbger.loadSymbolsFromFile(dbger.path, 0); err != nil {
		return fmt.Errorf("failed to load main symbols: %v", err)
	}

	if err := dbger.analyzePLTGOT(dbger.path); err != nil {
		Printf("Warning: failed to analyze PLT/GOT: %v\n", err)
	}

	libs, err := dbger.ldd()
	if err != nil {
		Printf("Warning: failed to get shared libraries: %v\n", err)
	} else {
		for _, lib := range libs {
			libRoot := rootStruct{
				name: lib,
				base: 0,
				end:  0,
				root: &symTree{p: make(map[uint8]*symTree)},
			}
			libRoots = append(libRoots, libRoot)

			libIndex := len(libRoots) - 1
			if err := dbger.loadSymbolsFromFile(lib, libIndex); err != nil {
				Printf("Warning: failed to load symbols from %s: %v\n", lib, err)
			}
		}
	}

	symTable.getSortedAddresses()
	Printf("Loaded %d symbols from %d libraries\n", len(symTable.symbols), len(libRoots))

	return nil
}

func (dbger *TypeDbg) loadSymbolsFromFile(filename string, libIndex int) error {
	file, err := elf.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := dbger.loadSymbolSection(file, ".symtab", ".strtab", libIndex); err != nil {
		// Printf("failed to load static symbols from %s: %v\n", filename, err)
	}

	if err := dbger.loadSymbolSection(file, ".dynsym", ".dynstr", libIndex); err != nil {
		// Printf("failed to load dynamic symbols from %s: %v\n", filename, err)
	}

	return nil
}

func (dbger *TypeDbg) loadSymbolSection(file *elf.File, symSecName, strSecName string, libIndex int) error {
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

	var symbols []elf.Symbol
	if symSecName == ".symtab" {
		symbols, err = file.Symbols()
	} else {
		symbols, err = file.DynamicSymbols()
	}
	if err != nil {
		return fmt.Errorf("failed to read symbols: %v", err)
	}

	for _, sym := range symbols {
		if sym.Name == "" {
			continue
		}

		symType := elf.SymType(sym.Info & 0xf)
		isImportantSymbol := strings.Contains(sym.Name, "_start") ||
			strings.Contains(sym.Name, "_end") ||
			strings.Contains(sym.Name, "main") ||
			strings.Contains(sym.Name, "__") ||
			symType == elf.STT_FUNC ||
			symType == elf.STT_OBJECT ||
			sym.Info>>4 == uint8(elf.STB_GLOBAL)

		if sym.Value == 0 && !isImportantSymbol {
			continue
		}

		if symType == elf.STT_FILE || symType == elf.STT_SECTION {
			continue
		}

		symbol := Symbol{
			Name:     sym.Name,
			Addr:     sym.Value,
			Size:     sym.Size,
			Type:     symType,
			Bind:     elf.SymBind(sym.Info >> 4),
			Section:  uint16(sym.Section),
			LibIndex: libIndex,
		}

		symTable.AddSymbol(symbol)
	}

	return nil
}

var resolvedN int = 0

func (dbger *TypeDbg) Reload() error {
	if len(libRoots) == 0 {
		return errors.New("no libraries loaded")
	} else if len(libRoots) == resolvedN {
		return nil
	}
	resolvedN = 0
	dbger.loadBase()

	isPie, err := dbger.isPIE()
	if err != nil {
		return err
	}

	if isPie {
		baseAddr, err := dbger.getBaseAddress(dbger.pid, libRoots[0].name)
		if err == nil {
			libRoots[0].base = baseAddr
			resolvedN++
		}
	}

	for i := 1; i < len(libRoots); i++ {
		baseAddr, err := dbger.getBaseAddress(dbger.pid, libRoots[i].name)
		if err == nil {
			libRoots[i].base = baseAddr
			resolvedN++
		}
	}

	if symTable != nil {
		newRangeMap := make(map[uint64]*Symbol)
		newAddrToSymbol := make(map[uint64]*Symbol)

		for _, sym := range symTable.symbols {
			actualAddr := sym.Addr
			if sym.LibIndex < len(libRoots) {
				actualAddr += libRoots[sym.LibIndex].base
			}
			newRangeMap[actualAddr] = &sym
			newAddrToSymbol[actualAddr] = &sym
		}

		symTable.rangeMap = newRangeMap
		symTable.addrToSymbol = newAddrToSymbol
		symTable.rangeDirty = true
		symTable.sortedAddrs = nil
	}

	buildLibraryRanges()

	return nil
}

func (dbger *TypeDbg) ResolveAddrToSymbol(addr uint64) (*Symbol, uint64, error) {
	if symTable == nil {
		return nil, 0, errors.New("symbols not loaded")
	}

	namePtr, offset, err := addr2Name(addr)
	if err != nil {
		return nil, 0, err
	}

	if sym, exists := symTable.nameToSymbol[*namePtr]; exists {
		return sym, offset, nil
	}

	return nil, 0, errors.New("symbol structure not found")
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
		actualAddr := sym.Addr
		if sym.LibIndex < len(libRoots) {
			actualAddr += libRoots[sym.LibIndex].base
		}
		libName := "unknown"
		if sym.LibIndex < len(libRoots) {
			libName = libRoots[sym.LibIndex].name
		}
		Printf("  %d: %s @ 0x%x (%s)\n", i, sym.Name, actualAddr, libName)
	}

	return matches[0], nil
}

func (dbger *TypeDbg) ListSymbols(filter string) error {
	if symTable == nil {
		return errors.New("symbols not loaded")
	}

	sortedAddrs := symTable.getSortedAddresses()

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

		fmt.Fprintf(file, "%-18s %-8s %-8s %-30s %s\n", "ADDRESS", "TYPE", "BIND", "LIBRARY", "NAME")
		fmt.Fprintf(file, "%s\n", strings.Repeat("-", 120))

		count := 0
		for _, actualAddr := range sortedAddrs {
			sym := symTable.rangeMap[actualAddr]
			libName := "unknown"
			if sym.LibIndex < len(libRoots) {
				libName = libRoots[sym.LibIndex].name
			}
			typeStr := symbolTypeString(sym.Type)
			bindStr := symbolBindString(sym.Bind)
			fmt.Fprintf(file, "0x%016x  %-8s %-8s %-30s %s\n", actualAddr, typeStr, bindStr, libName, sym.Name)
			count++
		}
		file.Close()

		cmd := exec.Command("less", "-SR", tempFile)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return err
		}

	} else {
		count := 0

		Printf("%-18s %-8s %-8s %-30s %s\n", "ADDRESS", "TYPE", "BIND", "LIBRARY", "NAME")
		Printf("%s\n", strings.Repeat("-", 120))

		for _, actualAddr := range sortedAddrs {
			sym := symTable.rangeMap[actualAddr]
			if !strings.Contains(strings.ToLower(sym.Name), strings.ToLower(filter)) {
				continue
			}

			libName := "unknown"
			if sym.LibIndex < len(libRoots) {
				libName = libRoots[sym.LibIndex].name
			}
			typeStr := symbolTypeString(sym.Type)
			bindStr := symbolBindString(sym.Bind)
			Printf("0x%016x  %-8s %-8s %-30s %s\n", actualAddr, typeStr, bindStr, libName, sym.Name)
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

	actualAddr := sym.Addr
	if sym.LibIndex < len(libRoots) {
		actualAddr += libRoots[sym.LibIndex].base
	}

	libName := "unknown"
	if sym.LibIndex < len(libRoots) {
		libName = libRoots[sym.LibIndex].name
	}

	Printf("Symbol: %s\n", sym.Name)
	Printf("Address: 0x%016x\n", actualAddr)
	Printf("Relative Address: 0x%016x\n", sym.Addr)
	Printf("Size: %d bytes\n", sym.Size)
	Printf("Type: %s\n", symbolTypeString(sym.Type))
	Printf("Bind: %s\n", symbolBindString(sym.Bind))
	Printf("Section: %d\n", sym.Section)
	Printf("Library: %s\n", libName)
	if sym.LibIndex < len(libRoots) {
		Printf("Base Address: 0x%016x\n", libRoots[sym.LibIndex].base)
	}

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

	libName := ""
	if sym.LibIndex < len(libRoots) {
		fullPath := libRoots[sym.LibIndex].name
		if idx := strings.LastIndex(fullPath, "/"); idx >= 0 {
			libName = fmt.Sprintf(" [%s]", fullPath[idx+1:])
		} else {
			libName = fmt.Sprintf(" [%s]", fullPath)
		}
	}

	if offset == 0 {
		Printf("0x%016x: %s%s\n", addr, sym.Name, libName)
	} else {
		Printf("0x%016x: %s+0x%x%s\n", addr, sym.Name, offset, libName)
	}
}

func (dbger *TypeDbg) AnalyzePLTGOTInfo() ([]PLTEntry, []GOTEntry, error) {
	if dbger.path == "" {
		return nil, nil, errors.New("invalid filename")
	}

	file, err := elf.Open(dbger.path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	dynSymbols, dynStrings, err := loadDynamicSymbols(file)
	if err != nil {
		return nil, nil, err
	}

	var pltEntries []PLTEntry
	var gotEntries []GOTEntry

	pltSection := file.Section(".plt.sec")
	if pltSection == nil {
		pltSection = file.Section(".plt")
	}

	if pltSection != nil {
		relPltSection := file.Section(".rela.plt")
		if relPltSection == nil {
			relPltSection = file.Section(".rel.plt")
		}

		if relPltSection != nil {
			relocations, err := parseRelocations(relPltSection, file)
			if err == nil {
				pltEntrySize := getPLTEntrySize(file.Machine)
				isModernPLT := (pltSection.Name == ".plt.sec")

				for i, reloc := range relocations {
					if reloc.SymbolIndex >= uint32(len(dynSymbols)) {
						continue
					}

					var pltEntryAddr uint64
					if isModernPLT {
						pltEntryAddr = pltSection.Addr + uint64(i*pltEntrySize)
					} else {
						pltEntryAddr = pltSection.Addr + uint64((i+1)*pltEntrySize)
					}

					symbol := dynSymbols[reloc.SymbolIndex]
					symbolName := getSymbolName(symbol.NameOffset, dynStrings)
					if symbolName == "" {
						continue
					}

					pltName := symbolName + "@plt"
					if reloc.Addend != 0 {
						pltName += fmt.Sprintf("+0x%x", reloc.Addend)
					}

					entry := PLTEntry{
						Address:      pltEntryAddr + libRoots[0].base,
						Name:         pltName,
						OriginalName: symbolName,
						Offset:       pltEntryAddr - pltSection.Addr,
						AddEnd:       reloc.Addend,
						IsSynthetic:  true,
					}
					pltEntries = append(pltEntries, entry)
				}
			}
		}
	}

	gotSection := file.Section(".got.plt")
	if gotSection == nil {
		gotSection = file.Section(".got")
	}

	if gotSection != nil {
		gotData, err := gotSection.Data()
		if err == nil {
			var entrySize int
			if file.Class == elf.ELFCLASS64 {
				entrySize = 8
			} else {
				entrySize = 4
			}

			entryCount := len(gotData) / entrySize
			byteOrder := getByteOrder(file)

			for i := 0; i < entryCount; i++ {
				entryData := gotData[i*entrySize : (i+1)*entrySize]
				var value uint64

				if entrySize == 8 {
					value = byteOrder.Uint64(entryData)
				} else {
					value = uint64(byteOrder.Uint32(entryData))
				}

				entry := GOTEntry{
					Address: gotSection.Addr + uint64(i*entrySize) + libRoots[0].base,
					Name:    fmt.Sprintf("GOT[%d]", i),
					Value:   value,
				}
				gotEntries = append(gotEntries, entry)
			}
		}
	}

	relDynSection := file.Section(".rela.dyn")
	if relDynSection == nil {
		relDynSection = file.Section(".rel.dyn")
	}

	if relDynSection != nil {
		dynRelocations, err := parseRelocations(relDynSection, file)
		if err == nil {
			for _, reloc := range dynRelocations {
				if reloc.SymbolIndex >= uint32(len(dynSymbols)) {
					continue
				}

				symbol := dynSymbols[reloc.SymbolIndex]
				symbolName := getSymbolName(symbol.NameOffset, dynStrings)
				if symbolName == "" {
					continue
				}

				for i := range gotEntries {
					if gotEntries[i].Address-libRoots[0].base == reloc.Offset {
						gotEntries[i].Name = symbolName
						break
					}
				}
			}
		}
	}

	return pltEntries, gotEntries, nil
}
