package main

import (
	"encoding/binary"
	"errors"
	"fastDbg/common"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"time"
)

func parseDumpArgs(args []string, defaultCount uint64) (uint64, uint64, error) {
	if len(args) < 3 {
		return 0, 0, errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return 0, 0, err
	}
	n := defaultCount
	if len(args) > 3 && args[3] != "" {
		n, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return 0, 0, err
		}
	}
	return addr, n, nil
}

func (dbger *TypeDbg) cmdDumpByte(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, n, err := parseDumpArgs(args, 64)
	if err != nil {
		return err
	}
	return common.DumpBytes(dbger, addr, uint(n), os.Stdout)
}

func (dbger *TypeDbg) cmdDumpDword(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, n, err := parseDumpArgs(args, 16)
	if err != nil {
		return err
	}
	return common.DumpDwords(dbger, addr, uint(n), os.Stdout)
}

func (dbger *TypeDbg) cmdDumpQword(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, n, err := parseDumpArgs(args, 8)
	if err != nil {
		return err
	}
	return common.DumpQwords(dbger, addr, uint(n), os.Stdout)
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
		if i+8 <= len(code) {
			address := binary.LittleEndian.Uint64(code[i : i+8])
			fmt.Fprintf(file, "%s0x%016x%s:+0x%03x(+0x%02x)|%s0x%016x%s%s\n",
				ColorBlue, addr+uint64(i), ColorReset,
				i, i/8,
				dbger.addr2color(address), address, ColorReset,
				dbger.addr2some(address))
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

func (dbger *TypeDbg) cmdVisualHeap(_ interface{}) error {
	snap, err := dbger.snapshotMainArena()
	if err != nil {
		return err
	}
	if snap.heap == nil {
		return errors.New("heap not found")
	}
	addr := snap.heapStart
	code := snap.heap

	tempFile := fmt.Sprintf("/tmp/fastDbg_%d_%d", os.Getpid(), time.Now().Unix())
	file, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	defer func() {
		file.Close()
		os.Remove(tempFile)
	}()

	tmap := snap.annotations()

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
					str, ok := tmap[addr+i+j]
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
	return dbger.cmdBinsImpl()
}
