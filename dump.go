package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

func (dbger *TypeDbg) cmdDumpByte(a interface{}) error {
	args, ok := a.([]string)
	if !ok || len(args) < 3 {
		return errors.New("invalid arguments")
	}

	var addr uint64
	var n uint64 = 64
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	if len(args) > 3 && args[3] != "" {
		n, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return err
		}
	}

	data, err := dbger.GetMemory(uint(n), uintptr(addr))
	if err != nil {
		return err
	}

	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%016x: ", addr+uint64(i))

		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Printf("   ")
			}
		}

		fmt.Printf(" |")

		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Printf(".")
			}
		}

		fmt.Printf("|\n")
	}

	return nil
}

func (dbger *TypeDbg) cmdDumpDword(a interface{}) error {
	args, ok := a.([]string)
	if !ok || len(args) < 3 {
		return errors.New("invalid arguments")
	}

	var addr uint64
	var n uint64 = 16
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	if len(args) > 3 && args[3] != "" {
		n, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return err
		}
	}

	data, err := dbger.GetMemory(uint(n*4), uintptr(addr))
	if err != nil {
		return err
	}

	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%016x: ", addr+uint64(i))

		for j := 0; j < 16; j += 4 {
			if len(data)-(i+j) >= 4 {
				fmt.Printf("0x%08x ", binary.LittleEndian.Uint32(data[i+j:i+j+4]))
			} else {
				fmt.Printf("           ")
			}
		}

		fmt.Printf(" |")

		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Printf(".")
			}
		}

		fmt.Printf("|\n")
	}

	return nil
}

func (dbger *TypeDbg) cmdDumpQword(a interface{}) error {
	args, ok := a.([]string)
	if !ok || len(args) < 3 {
		return errors.New("invalid arguments")
	}

	var addr uint64
	var n uint64 = 8
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	if len(args) > 3 && args[3] != "" {
		n, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return err
		}
	}

	data, err := dbger.GetMemory(uint(n*8), uintptr(addr))
	if err != nil {
		return err
	}

	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%016x: ", addr+uint64(i))

		for j := 0; j < 16; j += 8 {
			if len(data)-(i+j) >= 8 {
				fmt.Printf("0x%016x ", binary.LittleEndian.Uint64(data[i+j:i+j+8]))
			} else {
				fmt.Printf("                   ")
			}
		}

		fmt.Printf(" |")

		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Printf(".")
			}
		}

		fmt.Printf("|\n")
	}

	return nil
}

var maxDeps int = 0

func (dbger *TypeDbg) addr2some(addr uint64) string {
	var ret string
	sym, off, err := dbger.ResolveAddrToSymbol(addr)
	color := dbger.addr2color(addr)
	if err == nil {
		if off == 0 {
			ret += fmt.Sprintf("%s<%s>%s", color, sym.Name, ColorReset)
		} else {
			ret += fmt.Sprintf("%s<%s+0x%x>%s", color, sym.Name, off, ColorReset)
		}
	}
	if color == ColorExecutable || color == ColorReadWriteExecutable || color == ColorReadExecutable {
		instr, err := dbger.disassOne(uintptr(addr))
		if err == nil {
			ret += fmt.Sprintf("%s->%s%s%s", ColorReset, color, *instr, ColorReset)
		}
	} else {
		code, err := dbger.GetMemory(8, uintptr(addr))
		if err == nil {
			ok := func() bool {
				nonZero := false
				for _, c := range code {
					if c == 0 {
						continue
					}
					nonZero = true
					if c < 0x20 || c > 0x7e {
						return false
					}
				}

				return nonZero
			}()
			if ok {
				ret += fmt.Sprintf("%s->%s\"%s\"%s", ColorReset, color, string(code), ColorReset)
			} else {
				newAddr := binary.LittleEndian.Uint64(code)
				ret += fmt.Sprintf("%s->%s0x%016x%s", ColorReset, dbger.addr2color(newAddr), newAddr, ColorReset)
				if maxDeps < 4 {
					ret += dbger.addr2some(newAddr)
					maxDeps++
				}
			}
		}
	}
	maxDeps = 0
	return ret
}

const (
	ColorReadWriteExecutable = ColorYellow
	ColorReadExecutable      = ColorRed
	ColorReadWrite           = ColorCyan
	ColorExecutable          = ColorPurple
	ColorRead                = ColorBlue
	ColorWrite               = ColorGreen
	ColorDefault             = ColorReset
)

func (dbger *TypeDbg) addr2color(addr uint64) string {
	idx := sort.Search(len(procMapsDetail), func(i int) bool {
		return procMapsDetail[i].end > addr
	})
	if idx < len(procMapsDetail) &&
		addr >= procMapsDetail[idx].start &&
		addr < procMapsDetail[idx].end {
		p := procMapsDetail[idx]
		if p.r && p.w && p.x {
			return ColorReadWriteExecutable // rwx
		}
		if p.r && p.w && !p.x {
			return ColorReadWrite // rw
		}
		if p.x {
			return ColorExecutable // x (with or without r)
		}
		if p.r && !p.w && !p.x {
			return ColorRead // r only
		}
		if p.w && !p.r && !p.x {
			return ColorWrite // w only
		}
		return ColorDefault
	}
	return ColorDefault
}

func (dbger *TypeDbg) cmdTelescope(a interface{}) error {
	args, ok := a.([]string)
	if !ok || len(args) < 3 {
		return errors.New("invalid arguments")
	}

	var addr uint64
	var n uint64 = 0x80
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	if len(args) > 3 && args[3] != "" {
		n, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return err
		}
	}

	tempFile := fmt.Sprintf("/tmp/fastDbg_%d_%d", os.Getpid(), time.Now().Unix())
	file, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	defer func() {
		file.Close()
		os.Remove(tempFile)
	}()

	code, err := dbger.GetMemory(uint(n*8), uintptr(addr))
	if err != nil {
		return err
	}

	for i := 0; i < len(code); i += 8 {
		if i+8 < len(code) {
			address := binary.LittleEndian.Uint64(code[i : i+8])
			fmt.Fprintf(file, "%s0x%016x%s:+0x%03x(+0x%02x)|%s0x%016x%s%s\n",
				ColorBlue, addr+uint64(i), ColorReset, i, i/8, dbger.addr2color(address),
				address,
				dbger.addr2some(address), ColorReset)
		}
	}
	file.Close()

	cmd := exec.Command("less", "-SR", tempFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// heap

const tcacheMaxBins = 64

type tcachePerThreadStruct struct {
	counts  [tcacheMaxBins]uint16
	entries [tcacheMaxBins]uint64
}

const (
	stateTrue = iota
	stateFalse
	stateUndefined
)

func (dbger *TypeDbg) cmdVisualHeap(_ interface{}) error {
	addr, sz, ok := func() (uint64, uint64, bool) {
		for _, p := range procMapsDetail {
			if strings.Contains(p.path, "heap") {
				return p.start, p.end - p.start, true
			}
		}
		return 0, 0, false
	}()
	if !ok {
		return errors.New("heap not found")
	}

	code, err := dbger.GetMemory(uint(sz), uintptr(addr))
	if err != nil {
		return err
	}

	tempFile := fmt.Sprintf("/tmp/fastDbg_%d_%d", os.Getpid(), time.Now().Unix())
	file, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	defer func() {
		file.Close()
		os.Remove(tempFile)
	}()

	isSafeLinking := stateUndefined
	// tcache
	tmap := func() *map[uint64]string {
		ret := make(map[uint64]string)
		if len(code) > tcacheMaxBins*2+tcacheMaxBins*8+0x10 {
			tpts := (*tcachePerThreadStruct)(unsafe.Pointer(&code[0x10]))
			for i, e := range tpts.entries {
				if e == 0 {
					continue
				}
				ret[e] = fmt.Sprintf("tcache[sz=0x%x][1/%d]", 0x20+0x10*i, tpts.counts[i])
				var curr uint64 = e
				for j := range tpts.counts[i] - 1 {
					tmp := binary.LittleEndian.Uint64(code[curr-addr : curr-addr+8])
					if isSafeLinking == stateUndefined {
						if tmp%0x10 != 0 {
							isSafeLinking = stateTrue
						} else {
							isSafeLinking = stateFalse
						}
					}
					if isSafeLinking == stateTrue {
						curr = tmp ^ (curr >> 12)
					} else {
						curr = tmp
					}
					ret[curr] = fmt.Sprintf("tcache[sz=0x%x][%d/%d]", 0x20+0x10*i, 2+j, tpts.counts[i])
					if curr == 0 || curr-addr > uint64(len(code)) {
						break
					}
				}
			}
		}

		return &ret
	}()

	var c int = 0
	for i := uint64(0); i < uint64(len(code)); {
		chkSz := binary.LittleEndian.Uint64(code[i+8 : i+16])
		chkSz = chkSz & 0xfffffffffffffff8
		color := colorArray[c%len(colorArray)]
		var zeroFlag bool = false
		var zeroSz int = 0
		for j := uint64(0); j < chkSz; j += 0x10 {
			if i+j+0x10 < uint64(len(code)) {
				v1 := binary.LittleEndian.Uint64(code[i+j : i+j+8])
				v2 := binary.LittleEndian.Uint64(code[i+j+8 : i+j+8+8])
				if zeroFlag {
					zeroSz += 0x10
				}
				if v1 == 0 && v2 == 0 {
					if zeroFlag && j+0x10 == chkSz {
						fmt.Fprintf(file, "%s[repeat 0 for +0x%x times]%s\n", color, zeroSz, ColorReset)
					} else {
						zeroFlag = true
					}
				} else {
					if zeroFlag && zeroSz >= 0x10 {
						fmt.Fprintf(file, "%s[repeat 0 for +0x%x times]%s\n", color, zeroSz, ColorReset)
					}
					zeroSz = 0
					zeroFlag = false
				}
				if zeroSz < 0x10 {
					str, ok := (*tmap)[addr+i+j]
					fmt.Fprintf(file, "%s0x%016x|+0x%05x|+0x%05x: 0x%016x 0x%016x | ", color, addr+i+j, j, i+j, v1, v2)
					for k := range uint64(0x10) {
						b := code[i+j+k]
						if b >= 32 && b <= 126 {
							fmt.Fprintf(file, "%c", b)
						} else {
							fmt.Fprintf(file, ".")
						}
					}
					if ok {
						fmt.Fprintf(file, " | <- %s%s\n", str, ColorReset)
					} else {
						fmt.Fprintf(file, " |%s\n", ColorReset)
					}
				}
			}
		}
		i += chkSz
		c++
	}

	file.Close()

	cmd := exec.Command("less", "-SR", tempFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func (dbger *TypeDbg) cmdBins(_ interface{}) error {
	hLine("tcache")
	addr, sz, ok := func() (uint64, uint64, bool) {
		for _, p := range procMapsDetail {
			if strings.Contains(p.path, "heap") {
				return p.start, p.end - p.start, true
			}
		}
		return 0, 0, false
	}()
	if !ok {
		return errors.New("heap not found")
	}

	code, err := dbger.GetMemory(uint(sz), uintptr(addr))
	if err != nil {
		return err
	}
	isSafeLinking := stateUndefined
	if len(code) > tcacheMaxBins*2+tcacheMaxBins*8+0x10 {
		tpts := (*tcachePerThreadStruct)(unsafe.Pointer(&code[0x10]))
		for i, e := range tpts.entries {
			if e == 0 {
				continue
			}
			fmt.Printf("tcache[sz=%s0x%x%s][n=%s%d%s]\n", ColorCyan, 0x20+0x10*i, ColorReset, ColorCyan, tpts.counts[i], ColorReset)
			fmt.Printf("%s0x%x%s -> ", ColorCyan, e, ColorReset)
			var curr uint64 = e
			for _ = range tpts.counts[i] - 1 {
				tmp := binary.LittleEndian.Uint64(code[curr-addr : curr-addr+8])
				if isSafeLinking == stateUndefined {
					if tmp%0x10 != 0 {
						isSafeLinking = stateTrue
					} else {
						isSafeLinking = stateFalse
					}
				}
				if isSafeLinking == stateTrue {
					curr = tmp ^ (curr >> 12)
				} else {
					curr = tmp
				}
				fmt.Printf("%s0x%x%s -> ", ColorCyan, curr, ColorReset)
				if curr == 0 || curr-addr > uint64(len(code)) {
					break
				}
			}
		}
	}

	return nil
}
