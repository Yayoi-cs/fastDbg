package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// FILE / _IO_jump_t / _IO_wide_data layout for glibc 2.35-2.41 on x86_64.
// These structs are stable across the supported glibc range; the offsets
// come straight from the source headers and don't need heuristics.
//
// We anchor on three symbols that every stripped libc still exports in
// .dynsym (versioned as @GLIBC_2.2.5): `_IO_2_1_stdin_`, `_IO_2_1_stdout_`,
// `_IO_2_1_stderr_`. From there, every pointer we display either resolves
// through the existing symbol table (vtable members, _IO_file_jumps,
// _IO_wfile_jumps — also exported) or is labelled structurally because we
// know which slot it came out of (`_IO_stdfile_N_lock`, `_IO_wide_data_N`).

const (
	stdioSizeofFILE     = 0xe0  // _IO_FILE_plus = FILE + vtable
	stdioSizeofJumpT    = 168   // 21 fn pointers
	stdioSizeofWideData = 0xe8  // _IO_wide_data including wide_vtable

	stdioOffVtable      = 0xd8
	stdioOffLock        = 0x88
	stdioOffWideData    = 0xa0
	stdioOffWideVtable  = 0xe0

	stdioColumnWidth = 44
)

type stdioField struct {
	offset int
	size   int // bytes; 0 means "skipped, display ..."
	name   string
}

var stdioFileFields = []stdioField{
	{0x00, 4, "_flags"},
	{0x08, 8, "_IO_read_ptr"},
	{0x10, 8, "_IO_read_end"},
	{0x18, 8, "_IO_read_base"},
	{0x20, 8, "_IO_write_base"},
	{0x28, 8, "_IO_write_ptr"},
	{0x30, 8, "_IO_write_end"},
	{0x38, 8, "_IO_buf_base"},
	{0x40, 8, "_IO_buf_end"},
	{0x48, 8, "_IO_save_base"},
	{0x50, 8, "_IO_backup_base"},
	{0x58, 8, "_IO_save_end"},
	{0x60, 8, "_markers"},
	{0x68, 8, "_chain"},
	{0x70, 4, "_fileno"},
	{0x74, 4, "_flags2"},
	{0x78, 8, "_old_offset"},
	{0x80, 2, "_cur_column"},
	{0x82, 1, "_vtable_offset"},
	{0x83, 1, "_shortbuf"},
	{0x88, 8, "_lock"},
	{0x90, 8, "_offset"},
	{0x98, 8, "_codecvt"},
	{0xa0, 8, "_wide_data"},
	{0xa8, 8, "_freeres_list"},
	{0xb0, 8, "_freeres_buf"},
	{0xb8, 8, "__pad5"},
	{0xc0, 4, "_mode"},
	{0xc4, 0, "_unused2"},
	{0xd8, 8, "vtable"},
}

var stdioJumpFields = []stdioField{
	{0x00, 8, "__dummy"},
	{0x08, 8, "__dummy2"},
	{0x10, 8, "__finish"},
	{0x18, 8, "__overflow"},
	{0x20, 8, "__underflow"},
	{0x28, 8, "__uflow"},
	{0x30, 8, "__pbackfail"},
	{0x38, 8, "__xsputn"},
	{0x40, 8, "__xsgetn"},
	{0x48, 8, "__seekoff"},
	{0x50, 8, "__seekpos"},
	{0x58, 8, "__setbuf"},
	{0x60, 8, "__sync"},
	{0x68, 8, "__doallocate"},
	{0x70, 8, "__read"},
	{0x78, 8, "__write"},
	{0x80, 8, "__seek"},
	{0x88, 8, "__close"},
	{0x90, 8, "__stat"},
	{0x98, 8, "__showmanyc"},
	{0xa0, 8, "__imbue"},
}

var stdioWideDataFields = []stdioField{
	{0x00, 8, "_IO_read_ptr"},
	{0x08, 8, "_IO_read_end"},
	{0x10, 8, "_IO_read_base"},
	{0x18, 8, "_IO_write_base"},
	{0x20, 8, "_IO_write_ptr"},
	{0x28, 8, "_IO_write_end"},
	{0x30, 8, "_IO_buf_base"},
	{0x38, 8, "_IO_buf_end"},
	{0x40, 8, "_IO_save_base"},
	{0x48, 8, "_IO_backup_base"},
	{0x50, 8, "_IO_save_end"},
	{0x58, 8, "_IO_state"},
	{0x60, 8, "_IO_last_state"},
	{0x68, 0, "_codecvt"},
	{0xd8, 4, "_shortbuf"},
	{0xe0, 8, "_wide_vtable"},
}

func (dbger *TypeDbg) cmdStdioDump(_ interface{}) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}

	streamNames := []string{"_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"}
	addrs := make([]uint64, 3)
	for i, name := range streamNames {
		sym, err := dbger.ResolveSymbolToAddr(name)
		if err != nil || sym == nil {
			return fmt.Errorf("symbol %q not found in dynsym (libc loaded?): %v", name, err)
		}
		a := sym.Addr
		if sym.LibIndex < len(libRoots) {
			a += libRoots[sym.LibIndex].base
		}
		addrs[i] = a
	}

	fileBufs := make([][]byte, 3)
	for i, a := range addrs {
		b, err := dbger.GetMemory(stdioSizeofFILE, uintptr(a))
		if err != nil {
			return fmt.Errorf("read %s @ 0x%x: %v", streamNames[i], a, err)
		}
		fileBufs[i] = b
	}

	// Manual labels for symbols not exported in dynsym. We learn them
	// structurally: stdin._lock IS `_IO_stdfile_0_lock` by construction, etc.
	labels := map[uint64]string{}
	for i, a := range addrs {
		labels[a] = streamNames[i]
		if v := readField(fileBufs[i], stdioOffLock, 8); v != 0 {
			labels[v] = fmt.Sprintf("_IO_stdfile_%d_lock", i)
		}
		if v := readField(fileBufs[i], stdioOffWideData, 8); v != 0 {
			labels[v] = fmt.Sprintf("_IO_wide_data_%d", i)
		}
	}

	// Header row: addresses + symbol of each stream.
	fmt.Printf("  off | %-15s : ", "member")
	for i, a := range addrs {
		cell := fmt.Sprintf("%s0x%016x%s <%s>", ColorGreen, a, ColorReset, streamNames[i])
		_ = i
		fmt.Print(padCell(cell, stdioColumnWidth))
	}
	fmt.Println()

	hLine("FILE")
	for _, f := range stdioFileFields {
		dbger.printStdioRow(f, fileBufs, labels)
	}

	// Follow FILE.vtable -> _IO_jump_t.
	vtableBufs := make([][]byte, 3)
	for i := range fileBufs {
		va := readField(fileBufs[i], stdioOffVtable, 8)
		if va == 0 {
			continue
		}
		if b, err := dbger.GetMemory(stdioSizeofJumpT, uintptr(va)); err == nil {
			vtableBufs[i] = b
		}
	}
	if anyNonNil(vtableBufs) {
		hLine("FILE->vtable")
		for _, f := range stdioJumpFields {
			dbger.printStdioRow(f, vtableBufs, labels)
		}
	}

	// Follow FILE._wide_data.
	wideBufs := make([][]byte, 3)
	for i := range fileBufs {
		wa := readField(fileBufs[i], stdioOffWideData, 8)
		if wa == 0 {
			continue
		}
		if b, err := dbger.GetMemory(stdioSizeofWideData, uintptr(wa)); err == nil {
			wideBufs[i] = b
		}
	}
	if anyNonNil(wideBufs) {
		hLine("FILE->_wide_data")
		for _, f := range stdioWideDataFields {
			dbger.printStdioRow(f, wideBufs, labels)
		}

		// Follow _wide_data._wide_vtable.
		wvBufs := make([][]byte, 3)
		for i := range wideBufs {
			if wideBufs[i] == nil {
				continue
			}
			wva := readField(wideBufs[i], stdioOffWideVtable, 8)
			if wva == 0 {
				continue
			}
			if b, err := dbger.GetMemory(stdioSizeofJumpT, uintptr(wva)); err == nil {
				wvBufs[i] = b
			}
		}
		if anyNonNil(wvBufs) {
			hLine("FILE->_wide_data->_wide_vtable")
			for _, f := range stdioJumpFields {
				dbger.printStdioRow(f, wvBufs, labels)
			}
		}
	}

	return nil
}

func (dbger *TypeDbg) printStdioRow(f stdioField, bufs [][]byte, labels map[uint64]string) {
	fmt.Printf("+0x%02x | %-15s : ", f.offset, f.name)
	for _, b := range bufs {
		fmt.Print(padCell(dbger.formatStdioCell(b, f, labels), stdioColumnWidth))
	}
	fmt.Println()
}

func (dbger *TypeDbg) formatStdioCell(buf []byte, f stdioField, labels map[uint64]string) string {
	if buf == nil {
		return ""
	}
	if f.size == 0 {
		return "..."
	}
	val := readField(buf, f.offset, f.size)

	var hexStr string
	switch f.size {
	case 1:
		hexStr = fmt.Sprintf("0x%02x", val)
	case 2:
		hexStr = fmt.Sprintf("0x%04x", val)
	case 4:
		hexStr = fmt.Sprintf("0x%08x", val)
	default:
		hexStr = fmt.Sprintf("0x%016x", val)
	}

	if f.size != 8 {
		return hexStr
	}
	if val == 0 {
		return hexStr
	}

	color := dbger.addr2color(val)
	name := labels[val]
	if name == "" {
		if sym, off, err := dbger.ResolveAddrToSymbol(val); err == nil && sym != nil && off == 0 {
			name = sym.Name
		}
	}
	if name != "" {
		return fmt.Sprintf("%s%s%s <%s>", color, hexStr, ColorReset, name)
	}
	return fmt.Sprintf("%s%s%s", color, hexStr, ColorReset)
}

func readField(buf []byte, offset, size int) uint64 {
	if offset+size > len(buf) {
		return 0
	}
	switch size {
	case 1:
		return uint64(buf[offset])
	case 2:
		return uint64(binary.LittleEndian.Uint16(buf[offset : offset+2]))
	case 4:
		return uint64(binary.LittleEndian.Uint32(buf[offset : offset+4]))
	case 8:
		return binary.LittleEndian.Uint64(buf[offset : offset+8])
	}
	return 0
}

// padCell right-pads s with spaces so its visible (ANSI-stripped) width is
// at least n. We strip ANSI CSI sequences (`\x1b[...m`) when measuring so
// colored cells line up with uncolored ones.
func padCell(s string, n int) string {
	v := visibleLen(s)
	if v >= n {
		return s + " "
	}
	return s + strings.Repeat(" ", n-v)
}

func visibleLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

func anyNonNil(bufs [][]byte) bool {
	for _, b := range bufs {
		if b != nil {
			return true
		}
	}
	return false
}
