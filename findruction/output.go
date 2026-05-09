package findruction

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
	"unsafe"
)

/*
#cgo pkg-config: capstone
#include <capstone/capstone.h>

static inline char* fr_mnemonic(cs_insn* insn) { return insn->mnemonic; }
static inline char* fr_op_str(cs_insn* insn)  { return insn->op_str; }
static inline uint64_t fr_address(cs_insn* insn) { return insn->address; }
*/
import "C"

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
)

// Insn is one decoded instruction. Kept separate from any rendering so
// both the less-style ANSI formatter and the tview formatter can share the
// disassembly path.
type Insn struct {
	Address  uint64
	Mnemonic string
	OpStr    string
}

// disassembleAt decodes up to `n` instructions from `bytes` starting at
// virtual address `vaddr`.
func disassembleAt(bytes []byte, vaddr uint64, n int) []Insn {
	if len(bytes) == 0 || n <= 0 {
		return nil
	}
	var handle C.csh
	if C.cs_open(C.CS_ARCH_X86, C.CS_MODE_64, &handle) != C.CS_ERR_OK {
		return nil
	}
	defer C.cs_close(&handle)

	var insn *C.cs_insn
	count := C.cs_disasm(handle,
		(*C.uint8_t)(unsafe.Pointer(&bytes[0])),
		C.size_t(len(bytes)),
		C.uint64_t(vaddr),
		C.size_t(n),
		&insn)
	if count == 0 {
		return nil
	}
	defer C.cs_free(insn, count)

	raw := (*[1 << 20]C.cs_insn)(unsafe.Pointer(insn))[:count]
	out := make([]Insn, 0, count)
	for i := 0; i < int(count); i++ {
		mn := C.fr_mnemonic(&raw[i])
		op := C.fr_op_str(&raw[i])
		mnStr := ""
		if mn != nil {
			mnStr = C.GoString(mn)
		}
		opStr := ""
		if op != nil {
			opStr = C.GoString(op)
		}
		out = append(out, Insn{
			Address:  uint64(C.fr_address(&raw[i])),
			Mnemonic: mnStr,
			OpStr:    opStr,
		})
	}
	return out
}

// formatInsnANSI renders a decoded instruction as a colored line for
// less-style output (ANSI escape codes).
func formatInsnANSI(in Insn) string {
	if in.OpStr != "" {
		return fmt.Sprintf("    %s0x%016x%s: %s%s%s %s", colorCyan, in.Address, colorReset, colorBlue, in.Mnemonic, colorReset, in.OpStr)
	}
	return fmt.Sprintf("    %s0x%016x%s: %s%s%s", colorCyan, in.Address, colorReset, colorBlue, in.Mnemonic, colorReset)
}

// fileBytesAt extracts up to `n` bytes starting at file offset `fileOff` of
// the given path. Used to feed disassembleAt for ELF-mode matches.
func fileBytesAt(path string, fileOff uint64, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if _, err := f.Seek(int64(fileOff), 0); err != nil {
		return nil
	}
	buf := make([]byte, n)
	got, err := f.Read(buf)
	if err != nil && got == 0 {
		return nil
	}
	return buf[:got]
}

// FormatGroups writes a structured listing of `groups` to `w`. Each group's
// matches are sorted by address and (when source is available) followed by
// up to `disasmCount` disassembled instructions for context.
//
// `viaMemory` controls how follow-up disassembly bytes are obtained:
//   - true: read from process memory via the supplied reader (used for
//     SearchMemoryRange results — vaddrs are absolute)
//   - false: read straight from the ELF file at FileOffset (used for
//     SearchAllLibraries results — vaddrs are file-internal)
func FormatGroups(w io.Writer, groups []Group, pattern []byte, disasmCount int, reader interface{ ReadMem(addr uint64, n int) []byte }) {
	totalMatches := 0
	for _, g := range groups {
		totalMatches += len(g.Matches)
	}
	fmt.Fprintf(w, "%sfindruction%s — %s%d%s match(es) across %s%d%s group(s); pattern = ",
		colorGreen, colorReset, colorCyan, totalMatches, colorReset, colorCyan, len(groups), colorReset)
	for _, b := range pattern {
		fmt.Fprintf(w, "%02x", b)
	}
	fmt.Fprintln(w)

	for gi, g := range groups {
		fmt.Fprintln(w)
		if g.Err != nil {
			fmt.Fprintf(w, "%s[%d] %s%s  %s<error: %v>%s\n", colorYellow, gi, g.Label, colorReset, colorRed, g.Err, colorReset)
			continue
		}
		fmt.Fprintf(w, "%s[%d] %s%s  %s(%d match(es), load_base=0x%x)%s\n",
			colorPurple, gi, g.Label, colorReset, colorCyan, len(g.Matches), g.LoadBase, colorReset)

		for mi, m := range g.Matches {
			abs := m.Vaddr
			if g.LoadBase != 0 {
				abs = g.LoadBase + m.Vaddr
			}
			fmt.Fprintf(w, "  %s#%d/%d%s  vaddr=%s0x%016x%s",
				colorGreen, mi+1, len(g.Matches), colorReset,
				colorCyan, abs, colorReset)
			if m.FileOffset != 0 {
				fmt.Fprintf(w, "  file_off=%s0x%x%s", colorBlue, m.FileOffset, colorReset)
			}
			fmt.Fprintln(w)

			if disasmCount <= 0 {
				continue
			}
			var bytes []byte
			if reader != nil {
				bytes = reader.ReadMem(abs, disasmCount*16)
			} else if g.Path != "" && m.FileOffset != 0 {
				bytes = fileBytesAt(g.Path, m.FileOffset, disasmCount*16)
			}
			for _, in := range disassembleAt(bytes, abs, disasmCount) {
				fmt.Fprintln(w, formatInsnANSI(in))
			}
		}
	}
}

// PageThroughLess writes `format` into a temp file then opens it with
// `less -SR` so colored output renders correctly and the user can scroll.
// This matches the existing pattern used by telescope and vis.
func PageThroughLess(format func(io.Writer)) error {
	tmp, err := os.CreateTemp("", fmt.Sprintf("findruction_%d_*.txt", time.Now().UnixNano()))
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	format(tmp)
	tmp.Close()

	cmd := exec.Command("less", "-SR", tmp.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
