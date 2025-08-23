package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
				fmt.Printf("0x%016x ", binary.LittleEndian.Uint32(data[i+j:i+j+8]))
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

func (dbger *TypeDbg) addr2some(addr uint64) string {
	var ret string
	for _, p := range procMapsDetail {
		if p.start <= addr && addr < p.end {
			sym, off, err := dbger.ResolveAddrToSymbol(addr)
			if err == nil {
				if off == 0 {
					ret += fmt.Sprintf("%s<%s>%s", ColorPurple, sym.Name, ColorReset)
				} else {
					ret += fmt.Sprintf("%s<%s+0x%x>%s", ColorPurple, sym.Name, off, ColorReset)
				}
			}
			if strings.Contains(p.rwx, "x") {
				instr, err := dbger.disassOne(uintptr(addr))
				if err == nil {
					ret += fmt.Sprintf("%s->%s%s%s", ColorReset, ColorRed, *instr, ColorReset)
				}
			} else {
				code, err := dbger.GetMemory(8, uintptr(addr))
				if err == nil {
					ok := func() bool {
						nonZero := false
						for c := range code {
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
						ret += fmt.Sprintf("%s->%s\"%s\"%s", ColorReset, ColorBlue, string(code), ColorReset)
					} else {
						newAddr := binary.LittleEndian.Uint64(code)
						ret += fmt.Sprintf("%s->%s0x%016x%s", ColorReset, ColorCyan, newAddr, ColorReset)
						ret += dbger.addr2some(newAddr)
					}
				}
			}
		}
	}
	return ret
}
