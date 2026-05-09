package common

import (
	"encoding/binary"
	"fmt"
	"io"
)

// DumpBytes prints `count` bytes of memory starting at `addr` to `w`,
// formatted xxd-style: 16 bytes per row, hex on the left, ASCII on the
// right. The address column is colored cyan to match the rest of the
// debugger.
func DumpBytes(r Reader, addr uint64, count uint, w io.Writer) error {
	data, err := r.GetMemory(count, uintptr(addr))
	if err != nil {
		return fmt.Errorf("read at 0x%x: %v", addr, err)
	}
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(w, "%s%016x%s: ", ColorBlue, addr+uint64(i), ColorReset)
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Fprintf(w, "%02x ", data[i+j])
			} else {
				fmt.Fprint(w, "   ")
			}
		}
		fmt.Fprint(w, " |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Fprintf(w, "%c", b)
			} else {
				fmt.Fprint(w, ".")
			}
		}
		fmt.Fprint(w, "|\n")
	}
	return nil
}

// DumpDwords prints `count` 32-bit dwords starting at `addr`, four per row,
// with the trailing ASCII column for each row.
func DumpDwords(r Reader, addr uint64, count uint, w io.Writer) error {
	data, err := r.GetMemory(count*4, uintptr(addr))
	if err != nil {
		return fmt.Errorf("read at 0x%x: %v", addr, err)
	}
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(w, "%s%016x%s: ", ColorBlue, addr+uint64(i), ColorReset)
		for j := 0; j < 16; j += 4 {
			if len(data)-(i+j) >= 4 {
				fmt.Fprintf(w, "%s0x%08x%s ", ColorCyan, binary.LittleEndian.Uint32(data[i+j:i+j+4]), ColorReset)
			} else {
				fmt.Fprint(w, "           ")
			}
		}
		fmt.Fprint(w, " |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Fprintf(w, "%c", b)
			} else {
				fmt.Fprint(w, ".")
			}
		}
		fmt.Fprint(w, "|\n")
	}
	return nil
}

// DumpQwords prints `count` 64-bit qwords starting at `addr`, two per row,
// with the trailing ASCII column.
func DumpQwords(r Reader, addr uint64, count uint, w io.Writer) error {
	data, err := r.GetMemory(count*8, uintptr(addr))
	if err != nil {
		return fmt.Errorf("read at 0x%x: %v", addr, err)
	}
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(w, "%s%016x%s: ", ColorBlue, addr+uint64(i), ColorReset)
		for j := 0; j < 16; j += 8 {
			if len(data)-(i+j) >= 8 {
				fmt.Fprintf(w, "%s0x%016x%s ", ColorCyan, binary.LittleEndian.Uint64(data[i+j:i+j+8]), ColorReset)
			} else {
				fmt.Fprint(w, "                   ")
			}
		}
		fmt.Fprint(w, " |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Fprintf(w, "%c", b)
			} else {
				fmt.Fprint(w, ".")
			}
		}
		fmt.Fprint(w, "|\n")
	}
	return nil
}
