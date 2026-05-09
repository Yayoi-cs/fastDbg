package qemu

import (
	"encoding/binary"
	"errors"
	"fastDbg/common"
	"fmt"
	"github.com/chzyer/readline"
	"golang.org/x/term"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type cmdHandler struct {
	regex *regexp.Regexp
	fn    func(*QemuDbg, interface{}) error
}

var compiledCmds = []cmdHandler{
	{regexp.MustCompile(`^\s*(b|break|B|BREAK)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*QemuDbg).cmdBreak},
	{regexp.MustCompile(`^\s*(p|print|P|PRINT)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*QemuDbg).cmdPrint},
	{regexp.MustCompile(`^\s*(db|xxd)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*QemuDbg).cmdXxd},
	{regexp.MustCompile(`^\s*(dd|xxd\s+dword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*QemuDbg).cmdXxdDword},
	{regexp.MustCompile(`^\s*(dq|xxd\s+qword)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*QemuDbg).cmdXxdQword},
	{regexp.MustCompile(`^\s*(disass)(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*QemuDbg).cmdDisass},
	{regexp.MustCompile(`^\s*(set)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*QemuDbg).cmdSet},
	{regexp.MustCompile(`^\s*(set32)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*QemuDbg).cmdSet32},
	{regexp.MustCompile(`^\s*(set16)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*QemuDbg).cmdSet16},
	{regexp.MustCompile(`^\s*(set8)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*QemuDbg).cmdSet8},
	{regexp.MustCompile(`^\s*(tel|telescope)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*QemuDbg).cmdTelescope},
	{regexp.MustCompile(`^\s*(stack|stk|STACK|STK)(\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*QemuDbg).cmdStack},
	{regexp.MustCompile(`^\s*(bt|backtrace|BT|BACKTRACE)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?$`), (*QemuDbg).cmdBacktrace},
	{regexp.MustCompile(`^\s*(pagetable|pt|PAGETABLE|PT)\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)$`), (*QemuDbg).cmdPageTable},
	{regexp.MustCompile(`^\s*(regs|registers)$`), (*QemuDbg).cmdRegs},
	{regexp.MustCompile(`^\s*(c|continue|cont|C|CONTINUE|CONT)\s*$`), (*QemuDbg).cmdContinue},
	{regexp.MustCompile(`^\s*(step|STEP)\s*$`), (*QemuDbg).cmdStep},
	{regexp.MustCompile(`^\s*(context|CONTEXT)\s*$`), (*QemuDbg).cmdContext},
	{regexp.MustCompile(`^\s*(kbase|KBASE)\s*$`), (*QemuDbg).cmdKbase},
	{regexp.MustCompile(`^\s*search-string\s+(\S+)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?\s*$`), (*QemuDbg).cmdSearchString},
	{regexp.MustCompile(`^\s*search-value\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0)(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?(?:\s+(0[xX][0-9a-fA-F]+|0[0-7]+|[1-9][0-9]*|0))?\s*$`), (*QemuDbg).cmdSearchValue},
}

func (q *QemuDbg) CmdExec(req string) error {
	for _, handler := range compiledCmds {
		if m := handler.regex.FindStringSubmatch(req); m != nil {
			return handler.fn(q, m)
		}
	}
	return errors.New("unknown command")
}

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

func LogError(msg string, a ...interface{}) {
	fmt.Printf("%s[ERROR]%s %s\n", ColorRed, ColorReset, fmt.Sprintf(msg, a...))
}

func Printf(msg string, a ...interface{}) {
	msg = strings.ReplaceAll(msg, "%d", "\033[36m%d\033[0m")
	msg = strings.ReplaceAll(msg, "0x%016x", "\033[36m0x%016x\033[0m")
	msg = strings.ReplaceAll(msg, "%016x", "\033[36m%016x\033[0m")
	msg = strings.ReplaceAll(msg, "%x", "\033[36m%x\033[0m")
	msg = strings.ReplaceAll(msg, "%s", "\033[32m%s\033[0m")
	fmt.Printf(msg, a...)
}

func cls() {
	fmt.Print("\033[2J")
	fmt.Print("\033[H")
}

func (q *QemuDbg) cmdBreak(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	err = q.SetBreakpoint(uintptr(addr))
	if err != nil {
		return err
	}

	fmt.Printf("Breakpoint set at %s0x%016x%s\n", ColorCyan, addr, ColorReset)
	return nil
}

func (q *QemuDbg) cmdPrint(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	val, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	fmt.Printf("HEX: %s0x%x%s DEC: %s%d%s OCT: %s%o%s BIN: %s%b%s\n",
		ColorCyan, val, ColorReset,
		ColorCyan, val, ColorReset,
		ColorCyan, val, ColorReset,
		ColorCyan, val, ColorReset)

	return nil
}

func parseXxdArgs(args []string, defaultN uint64) (uint64, uint64, error) {
	if len(args) < 3 {
		return 0, 0, errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return 0, 0, err
	}
	n := defaultN
	if len(args) > 3 && args[3] != "" {
		n, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return 0, 0, err
		}
	}
	return addr, n, nil
}

func (q *QemuDbg) cmdXxd(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, n, err := parseXxdArgs(args, 64)
	if err != nil {
		return err
	}
	return common.DumpBytes(q, addr, uint(n), os.Stdout)
}

func (q *QemuDbg) cmdXxdDword(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, n, err := parseXxdArgs(args, 16)
	if err != nil {
		return err
	}
	return common.DumpDwords(q, addr, uint(n), os.Stdout)
}

func (q *QemuDbg) cmdXxdQword(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, n, err := parseXxdArgs(args, 8)
	if err != nil {
		return err
	}
	return common.DumpQwords(q, addr, uint(n), os.Stdout)
}

func (q *QemuDbg) cmdDisass(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	var addr uint64
	var err error
	if len(args[2]) == 0 {
		addr, err = q.GetRip()
		if err != nil {
			return err
		}
	} else {
		addr, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return err
		}
	}

	var sz uint64 = 32
	if args[4] != "" {
		sz, err = strconv.ParseUint(args[5], 0, 32)
		if err != nil {
			return err
		}
	}

	return q.disass(addr, uint(sz))
}

func (q *QemuDbg) cmdSet(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	val, err := strconv.ParseUint(args[3], 0, 64)
	if err != nil {
		return err
	}

	valBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(valBytes, val)

	err = q.SetMemory(valBytes, uintptr(addr))
	if err != nil {
		return err
	}

	fmt.Printf("Set %s0x%016x%s = %s0x%016x%s\n", ColorBlue, addr, ColorReset, ColorCyan, val, ColorReset)
	return nil
}

func (q *QemuDbg) cmdSet32(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	val, err := strconv.ParseUint(args[3], 0, 32)
	if err != nil {
		return err
	}

	valBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valBytes, uint32(val))

	err = q.SetMemory(valBytes, uintptr(addr))
	if err != nil {
		return err
	}

	fmt.Printf("Set %s0x%016x%s = %s0x%08x%s\n", ColorBlue, addr, ColorReset, ColorCyan, val, ColorReset)
	return nil
}

func (q *QemuDbg) cmdSet16(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	val, err := strconv.ParseUint(args[3], 0, 16)
	if err != nil {
		return err
	}

	valBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(valBytes, uint16(val))

	err = q.SetMemory(valBytes, uintptr(addr))
	if err != nil {
		return err
	}

	fmt.Printf("Set %s0x%016x%s = %s0x%04x%s\n", ColorBlue, addr, ColorReset, ColorCyan, val, ColorReset)
	return nil
}

func (q *QemuDbg) cmdSet8(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	val, err := strconv.ParseUint(args[3], 0, 8)
	if err != nil {
		return err
	}

	valBytes := []byte{byte(val)}

	err = q.SetMemory(valBytes, uintptr(addr))
	if err != nil {
		return err
	}

	fmt.Printf("Set %s0x%016x%s = %s0x%02x%s\n", ColorBlue, addr, ColorReset, ColorCyan, val, ColorReset)
	return nil
}

func (q *QemuDbg) cmdRegs(a interface{}) error {
	regs, err := q.GetRegs()
	if err != nil {
		return err
	}

	fmt.Printf("$rax   : %s0x%016x%s\n", ColorCyan, regs.Rax, ColorReset)
	fmt.Printf("$rbx   : %s0x%016x%s\n", ColorCyan, regs.Rbx, ColorReset)
	fmt.Printf("$rcx   : %s0x%016x%s\n", ColorCyan, regs.Rcx, ColorReset)
	fmt.Printf("$rdx   : %s0x%016x%s\n", ColorCyan, regs.Rdx, ColorReset)
	fmt.Printf("$rsp   : %s0x%016x%s\n", ColorCyan, regs.Rsp, ColorReset)
	fmt.Printf("$rbp   : %s0x%016x%s\n", ColorCyan, regs.Rbp, ColorReset)
	fmt.Printf("$rsi   : %s0x%016x%s\n", ColorCyan, regs.Rsi, ColorReset)
	fmt.Printf("$rdi   : %s0x%016x%s\n", ColorCyan, regs.Rdi, ColorReset)
	fmt.Printf("$rip   : %s0x%016x%s\n", ColorCyan, regs.Rip, ColorReset)
	fmt.Printf("$r8    : %s0x%016x%s\n", ColorCyan, regs.R8, ColorReset)
	fmt.Printf("$r9    : %s0x%016x%s\n", ColorCyan, regs.R9, ColorReset)
	fmt.Printf("$r10   : %s0x%016x%s\n", ColorCyan, regs.R10, ColorReset)
	fmt.Printf("$r11   : %s0x%016x%s\n", ColorCyan, regs.R11, ColorReset)
	fmt.Printf("$r12   : %s0x%016x%s\n", ColorCyan, regs.R12, ColorReset)
	fmt.Printf("$r13   : %s0x%016x%s\n", ColorCyan, regs.R13, ColorReset)
	fmt.Printf("$r14   : %s0x%016x%s\n", ColorCyan, regs.R14, ColorReset)
	fmt.Printf("$r15   : %s0x%016x%s\n", ColorCyan, regs.R15, ColorReset)
	fmt.Printf("$eflags: %s0x%016x%s\n", ColorCyan, regs.Eflags, ColorReset)
	fmt.Printf("$cs: %x $ss: %x $ds: %x $es: %x $fs: %x $gs: %x\n",
		regs.Cs, regs.Ss, regs.Ds, regs.Es, regs.Fs, regs.Gs)

	return nil
}

func (q *QemuDbg) cmdContinue(a interface{}) error {
	fmt.Println("Continuing...")
	return q.Continue()
}

func (q *QemuDbg) cmdStep(a interface{}) error {
	err := q.Step()
	if err != nil {
		return err
	}
	cls()
	return q.cmdContext(nil)
}

func (q *QemuDbg) cmdTelescope(a interface{}) error {
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

	data, err := q.GetMemory(uint(n*8), uintptr(addr))
	if err != nil {
		return err
	}

	tempFile := fmt.Sprintf("/tmp/fastDbg_qemu_%d_%d", os.Getpid(), time.Now().Unix())
	file, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	defer func() {
		file.Close()
		os.Remove(tempFile)
	}()

	for i := 0; i < len(data); i += 8 {
		if i+8 <= len(data) {
			address := binary.LittleEndian.Uint64(data[i : i+8])
			fmt.Fprintf(file, "%s0x%016x%s:+0x%03x(+0x%02x)| %s0x%016x%s\n",
				ColorBlue, addr+uint64(i), ColorReset,
				i, i/8,
				ColorCyan, address, ColorReset)
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

func (q *QemuDbg) cmdStack(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	var sz uint64 = 16
	var err error
	if len(args[2]) != 0 {
		sz, err = strconv.ParseUint(args[3], 0, 64)
		if err != nil {
			return err
		}
	}

	regs, err := q.GetRegs()
	if err != nil {
		return err
	}

	rsp := regs.Rsp
	data, err := q.GetMemory(uint(sz*8), uintptr(rsp))
	if err != nil {
		return fmt.Errorf("error while getting stack memory: %v", err)
	}

	for i := 0; i < len(data); i += 8 {
		if i+8 <= len(data) {
			fmt.Printf("%s0x%016x%s: %s0x%016x%s\n",
				ColorBlue, rsp+uint64(i), ColorReset,
				ColorCyan, binary.LittleEndian.Uint64(data[i:i+8]), ColorReset)
		}
	}

	return nil
}

func (q *QemuDbg) cmdBacktrace(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	maxDepth := 20
	var err error
	if len(args) > 2 && len(args[2]) != 0 {
		depth, err := strconv.ParseUint(args[2], 0, 64)
		if err != nil {
			return fmt.Errorf("invalid depth: %v", err)
		}
		maxDepth = int(depth)
	}

	regs, err := q.GetRegs()
	if err != nil {
		return err
	}

	rip := regs.Rip
	rbp := regs.Rbp

	frameNum := 0
	fmt.Printf("#%-2d %s0x%016x%s\n", frameNum, ColorCyan, rip, ColorReset)

	visited := make(map[uint64]bool)
	visited[rbp] = true

	for frameNum = 1; frameNum < maxDepth; frameNum++ {
		if rbp == 0 || rbp%8 != 0 {
			break
		}

		ripData, err := q.GetMemory(8, uintptr(rbp+8))
		if err != nil {
			break
		}

		if len(ripData) < 8 {
			break
		}

		savedRip := binary.LittleEndian.Uint64(ripData)
		if savedRip == 0 {
			break
		}

		fmt.Printf("#%-2d %s0x%016x%s\n", frameNum, ColorCyan, savedRip, ColorReset)

		rbpData, err := q.GetMemory(8, uintptr(rbp))
		if err != nil {
			break
		}

		if len(rbpData) < 8 {
			break
		}

		prevRbp := binary.LittleEndian.Uint64(rbpData)
		if visited[prevRbp] {
			break
		}
		if prevRbp <= rbp {
			break
		}

		visited[prevRbp] = true
		rbp = prevRbp
	}

	return nil
}

func (q *QemuDbg) cmdContext(a interface{}) error {
	hLine("registers")

	if err := q.cmdRegs(nil); err != nil {
		return err
	}

	hLine("disassembly")
	regs, err := q.GetRegs()
	if err != nil {
		return err
	}

	q.disass(regs.Rip, 32)

	hLine("stack")
	data, err := q.GetMemory(64, uintptr(regs.Rsp))
	if err == nil {
		for i := 0; i < len(data); i += 8 {
			if i+8 <= len(data) {
				address := binary.LittleEndian.Uint64(data[i : i+8])
				fmt.Printf("%s0x%016x%s: %s0x%016x%s\n",
					ColorBlue, regs.Rsp+uint64(i), ColorReset,
					ColorCyan, address, ColorReset)
			}
		}
	}

	hLineRaw()
	return nil
}

func hLine(msg string) {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		w, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err == nil && w > 0 {
			fmt.Printf(strings.Repeat("-", (w-len(msg)-2)/2) + "[" + msg + "]" + strings.Repeat("-", (w-len(msg)-2)/2) + "\n")
			return
		}
	}
	fmt.Printf("[" + msg + "]\n")
}

func hLineRaw() {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		w, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err == nil && w > 0 {
			fmt.Println(strings.Repeat("-", w))
			return
		}
	}
	fmt.Println(strings.Repeat("-", 80))
}

func (q *QemuDbg) cmdPageTable(a interface{}) error {
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}

	vaddr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}

	cr3, err := q.GetCR3()
	if err != nil {
		return fmt.Errorf("failed to read CR3: %v", err)
	}

	pgdBasePhys := cr3 & 0x000FFFFFFFFFF000

	fmt.Printf("%sPage Table Walk for Virtual Address: 0x%016x%s\n", ColorCyan, vaddr, ColorReset)
	fmt.Printf("%sCR3 (Page Table Base): 0x%016x%s\n\n", ColorGreen, cr3, ColorReset)

	pgdIdx := (vaddr >> 39) & 0x1FF // bits 47:39
	pudIdx := (vaddr >> 30) & 0x1FF // bits 38:30
	pmdIdx := (vaddr >> 21) & 0x1FF // bits 29:21
	pteIdx := (vaddr >> 12) & 0x1FF // bits 20:12
	offset := vaddr & 0xFFF         // bits 11:0

	fmt.Printf("%sVirtual Address Breakdown:%s\n", ColorYellow, ColorReset)
	fmt.Printf("  PGD Index: 0x%03x (%d)\n", pgdIdx, pgdIdx)
	fmt.Printf("  PUD Index: 0x%03x (%d)\n", pudIdx, pudIdx)
	fmt.Printf("  PMD Index: 0x%03x (%d)\n", pmdIdx, pmdIdx)
	fmt.Printf("  PTE Index: 0x%03x (%d)\n", pteIdx, pteIdx)
	fmt.Printf("  Offset:    0x%03x (%d)\n\n", offset, offset)

	pgdEntryPhysAddr := pgdBasePhys + (pgdIdx * 8)
	pgdEntryData, err := q.GetPhysMemory(8, uintptr(pgdEntryPhysAddr))
	if err != nil {
		return fmt.Errorf("failed to read PGD entry at physical address 0x%x: %v", pgdEntryPhysAddr, err)
	}
	pgdEntry := binary.LittleEndian.Uint64(pgdEntryData)

	fmt.Printf("%s[PGD/PML4] Physical Address: 0x%016x%s\n", ColorBlue, pgdEntryPhysAddr, ColorReset)
	fmt.Printf("  Entry Value: %s0x%016x%s\n", ColorCyan, pgdEntry, ColorReset)
	q.printPageEntryFlags(pgdEntry)

	if (pgdEntry & 0x1) == 0 {
		return fmt.Errorf("%sPage not present at PGD level%s", ColorRed, ColorReset)
	}

	pudBasePhys := pgdEntry & 0x000FFFFFFFFFF000
	pudEntryPhysAddr := pudBasePhys + (pudIdx * 8)
	pudEntryData, err := q.GetPhysMemory(8, uintptr(pudEntryPhysAddr))
	if err != nil {
		return fmt.Errorf("failed to read PUD entry at physical address 0x%x: %v", pudEntryPhysAddr, err)
	}
	pudEntry := binary.LittleEndian.Uint64(pudEntryData)

	fmt.Printf("\n%s[PUD/PDP] Physical Address: 0x%016x%s\n", ColorBlue, pudEntryPhysAddr, ColorReset)
	fmt.Printf("  Entry Value: %s0x%016x%s\n", ColorCyan, pudEntry, ColorReset)
	q.printPageEntryFlags(pudEntry)

	if (pudEntry & 0x1) == 0 {
		return fmt.Errorf("%sPage not present at PUD level%s", ColorRed, ColorReset)
	}

	if (pudEntry & 0x80) != 0 {
		pageFrame := pudEntry & 0x000FFFFFC0000000
		physAddr := pageFrame + (vaddr & 0x3FFFFFFF)
		fmt.Printf("\n%s1GB Huge Page detected!%s\n", ColorGreen, ColorReset)
		fmt.Printf("%sPhysical Address: 0x%016x%s\n", ColorGreen, physAddr, ColorReset)
		return nil
	}

	pmdBasePhys := pudEntry & 0x000FFFFFFFFFF000
	pmdEntryPhysAddr := pmdBasePhys + (pmdIdx * 8)
	pmdEntryData, err := q.GetPhysMemory(8, uintptr(pmdEntryPhysAddr))
	if err != nil {
		return fmt.Errorf("failed to read PMD entry at physical address 0x%x: %v", pmdEntryPhysAddr, err)
	}
	pmdEntry := binary.LittleEndian.Uint64(pmdEntryData)

	fmt.Printf("\n%s[PMD/PD] Physical Address: 0x%016x%s\n", ColorBlue, pmdEntryPhysAddr, ColorReset)
	fmt.Printf("  Entry Value: %s0x%016x%s\n", ColorCyan, pmdEntry, ColorReset)
	q.printPageEntryFlags(pmdEntry)

	if (pmdEntry & 0x1) == 0 {
		return fmt.Errorf("%sPage not present at PMD level%s", ColorRed, ColorReset)
	}

	if (pmdEntry & 0x80) != 0 {
		pageFrame := pmdEntry & 0x000FFFFFFFE00000
		physAddr := pageFrame + (vaddr & 0x1FFFFF)
		fmt.Printf("\n%s2MB Huge Page detected!%s\n", ColorGreen, ColorReset)
		fmt.Printf("%sPhysical Address: 0x%016x%s\n", ColorGreen, physAddr, ColorReset)
		return nil
	}

	pteBasePhys := pmdEntry & 0x000FFFFFFFFFF000
	pteEntryPhysAddr := pteBasePhys + (pteIdx * 8)
	pteEntryData, err := q.GetPhysMemory(8, uintptr(pteEntryPhysAddr))
	if err != nil {
		return fmt.Errorf("failed to read PTE entry at physical address 0x%x: %v", pteEntryPhysAddr, err)
	}
	pteEntry := binary.LittleEndian.Uint64(pteEntryData)

	fmt.Printf("\n%s[PTE/PT] Physical Address: 0x%016x%s\n", ColorBlue, pteEntryPhysAddr, ColorReset)
	fmt.Printf("  Entry Value: %s0x%016x%s\n", ColorCyan, pteEntry, ColorReset)
	q.printPageEntryFlags(pteEntry)

	if (pteEntry & 0x1) == 0 {
		return fmt.Errorf("%sPage not present at PTE level%s", ColorRed, ColorReset)
	}

	pageFrame := pteEntry & 0x000FFFFFFFFFF000
	physAddr := pageFrame + offset

	fmt.Printf("\n%s[Result]%s\n", ColorGreen, ColorReset)
	fmt.Printf("  Page Frame: %s0x%016x%s\n", ColorCyan, pageFrame, ColorReset)
	fmt.Printf("  Physical Address: %s0x%016x%s\n", ColorGreen, physAddr, ColorReset)

	return nil
}

func (q *QemuDbg) printPageEntryFlags(entry uint64) {
	flags := []string{}
	if (entry & 0x1) != 0 {
		flags = append(flags, "P")
	}
	if (entry & 0x2) != 0 {
		flags = append(flags, "RW")
	} else {
		flags = append(flags, "RO")
	}
	if (entry & 0x4) != 0 {
		flags = append(flags, "U")
	} else {
		flags = append(flags, "S")
	}
	if (entry & 0x8) != 0 {
		flags = append(flags, "PWT")
	}
	if (entry & 0x10) != 0 {
		flags = append(flags, "PCD")
	}
	if (entry & 0x20) != 0 {
		flags = append(flags, "A")
	}
	if (entry & 0x40) != 0 {
		flags = append(flags, "D")
	}
	if (entry & 0x80) != 0 {
		flags = append(flags, "PS")
	}
	if (entry & 0x100) != 0 {
		flags = append(flags, "G")
	}
	if (entry & 0x8000000000000000) != 0 {
		flags = append(flags, "NX")
	}

	fmt.Printf("  Flags: %s[%s]%s\n", ColorYellow, strings.Join(flags, " | "), ColorReset)
	fmt.Printf("    P=Present, RW=Read/Write, RO=Read-Only, U=User, S=Supervisor\n")
	fmt.Printf("    PWT=WriteThrough, PCD=CacheDisable, A=Accessed, D=Dirty\n")
	fmt.Printf("    PS=PageSize, G=Global, NX=NoExecute\n")
}

func (q *QemuDbg) resolveSymbols(cmd string) (string, error) {
	resolver := NewQemuSymbolResolver(q)
	return ResolveSymbolsInCommand(cmd, resolver)
}

func (q *QemuDbg) Interactive() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	defer signal.Stop(sigChan)

	go func() {
		for range sigChan {
			Printf("\n^C - Interrupting QEMU target...\n")
			if err := q.Interrupt(); err != nil {
				LogError("Failed to interrupt QEMU target: %v", err)
			}
		}
	}()

	prev := ""

	rl, err := readline.NewEx(&readline.Config{
		Prompt:            "[fastDbg-QEMU]$ ",
		HistoryFile:       "/tmp/fastdbg_qemu_history.txt",
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
		FuncFilterInputRune: func(r rune) (rune, bool) {
			switch r {
			case readline.CharCtrlZ:
				return r, false
			}
			return r, true
		},
	})
	if err != nil {
		panic(err)
	}
	defer rl.Close()

	if err := q.cmdContext(nil); err != nil {
		LogError("Failed to get initial context: %v", err)
	}

	for {
		regs, err := q.GetRegs()
		if err == nil {
			rl.SetPrompt(fmt.Sprintf("[%sfastDbg%s:%s0x%x%s]$ ", ColorCyan, ColorReset, ColorCyan, regs.Rip, ColorReset))
		} else {
			rl.SetPrompt("[fastDbg]$ ")
		}

		req, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if err := q.Interrupt(); err != nil {
					LogError("Failed to interrupt QEMU target: %v", err)
				} else {
					if err := q.cmdContext(nil); err != nil {
						LogError("Failed to get context: %v", err)
					}
				}
				continue
			}
			if err == io.EOF {
				break
			}
			continue
		}

		if req == "" {
			if prev == "" {
				continue
			}
			req = prev
		}

		if req == "q" || req == "exit" || req == "quit" {
			break
		}

		prev = req

		resolvedReq := req
		if strings.Contains(req, "$") {
			resolvedReq, _ = q.resolveSymbols(req)
		}

		err = q.CmdExec(resolvedReq)
		if err != nil {
			LogError(err.Error())
		}
	}
}

func (q *QemuDbg) cmdKbase(_ interface{}) error {
	// Linux x86_64 KASLR places the kernel image at a 2MB-aligned address inside
	// the kernel-text region [0xffffffff80000000, 0xffffffff9fffffff]. That's
	// exactly 256 candidate positions. We probe each from the top down; the
	// lowest 2MB-aligned address that responds to a memory read is the kernel
	// base. RIP is intentionally NOT used as a starting point — it's often in
	// module space (≥0xffffffffa0000000) where walking downward crosses
	// unmapped gaps before reaching the kernel image.
	const (
		kernelTextStart uint64 = 0xffffffff80000000
		kernelTextEnd   uint64 = 0xffffffff9fffffff
		align2MB        uint64 = 0x200000
	)

	var kbase uint64
	for addr := kernelTextEnd & ^(align2MB - 1); ; addr -= align2MB {
		if _, err := q.GetMemory(1, uintptr(addr)); err == nil {
			kbase = addr
		}
		if addr <= kernelTextStart {
			break
		}
	}

	if kbase == 0 {
		return errors.New("kbase not found in kernel text range")
	}
	fmt.Printf("kbase = %s0x%016x%s\n", ColorCyan, kbase, ColorReset)
	return nil
}

// ---- search-string / search-value (kernel) ------------------------------

func (q *QemuDbg) cmdSearchString(a interface{}) error {
	args, ok := a.([]string)
	if !ok || len(args) < 4 {
		return errors.New("invalid arguments")
	}
	pattern := []byte(args[1])
	start, end, err := parseQemuRange(args[2], args[3])
	if err != nil {
		return err
	}
	return q.searchAndPrint(pattern, start, end, fmt.Sprintf("%q", string(pattern)))
}

func (q *QemuDbg) cmdSearchValue(a interface{}) error {
	args, ok := a.([]string)
	if !ok || len(args) < 4 {
		return errors.New("invalid arguments")
	}
	v, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return fmt.Errorf("invalid value: %v", err)
	}
	pattern := common.ValueToBytes(v)
	start, end, errR := parseQemuRange(args[2], args[3])
	if errR != nil {
		return errR
	}
	return q.searchAndPrint(pattern, start, end, fmt.Sprintf("0x%x", v))
}

func parseQemuRange(s, e string) (uint64, uint64, error) {
	var start, end uint64
	var err error
	if s != "" {
		start, err = strconv.ParseUint(s, 0, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid start: %v", err)
		}
	}
	if e != "" {
		end, err = strconv.ParseUint(e, 0, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid end: %v", err)
		}
	}
	if start != 0 && end != 0 && start >= end {
		return 0, 0, fmt.Errorf("start (0x%x) must be < end (0x%x)", start, end)
	}
	return start, end, nil
}

func (q *QemuDbg) searchAndPrint(pattern []byte, start, end uint64, label string) error {
	if len(pattern) == 0 {
		return errors.New("empty pattern")
	}
	if start == 0 {
		// Default: kernel-half virtual address space (text + modules + vmalloc).
		// SearchRange skips unmapped pages so the empty regions don't kill us.
		start = 0xffffffff80000000
	}
	if end == 0 {
		end = 0xffffffffffffffff
	}

	fmt.Printf("Searching [0x%x, 0x%x) for %s (%d bytes)...\n", start, end, label, len(pattern))
	hits := common.SearchRange(q, start, end, pattern)

	fmt.Printf("Found %s%d%s match(es)\n", ColorCyan, len(hits), ColorReset)
	const maxShow = 200
	for i, addr := range hits {
		if i >= maxShow {
			fmt.Printf("  ... %d more (truncated)\n", len(hits)-maxShow)
			break
		}
		fmt.Printf("  %s0x%016x%s\n", ColorCyan, addr, ColorReset)
	}
	return nil
}
