package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
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
