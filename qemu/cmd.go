package qemu

import (
	"encoding/binary"
	"errors"
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
	{regexp.MustCompile(`^\s*(regs|registers)$`), (*QemuDbg).cmdRegs},
	{regexp.MustCompile(`^\s*(c|continue|cont|C|CONTINUE|CONT)\s*$`), (*QemuDbg).cmdContinue},
	{regexp.MustCompile(`^\s*(step|STEP)\s*$`), (*QemuDbg).cmdStep},
	{regexp.MustCompile(`^\s*(context|CONTEXT)\s*$`), (*QemuDbg).cmdContext},
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

func (q *QemuDbg) cmdXxd(a interface{}) error {
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

	data, err := q.GetMemory(uint(n), uintptr(addr))
	if err != nil {
		return err
	}

	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%s%016x%s: ", ColorBlue, addr+uint64(i), ColorReset)

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

func (q *QemuDbg) cmdXxdDword(a interface{}) error {
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

	data, err := q.GetMemory(uint(n*4), uintptr(addr))
	if err != nil {
		return err
	}

	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%s%016x%s: ", ColorBlue, addr+uint64(i), ColorReset)

		for j := 0; j < 16; j += 4 {
			if len(data)-(i+j) >= 4 {
				fmt.Printf("%s0x%08x%s ", ColorCyan, binary.LittleEndian.Uint32(data[i+j:i+j+4]), ColorReset)
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

func (q *QemuDbg) cmdXxdQword(a interface{}) error {
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

	data, err := q.GetMemory(uint(n*8), uintptr(addr))
	if err != nil {
		return err
	}

	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%s%016x%s: ", ColorBlue, addr+uint64(i), ColorReset)

		for j := 0; j < 16; j += 8 {
			if len(data)-(i+j) >= 8 {
				fmt.Printf("%s0x%016x%s ", ColorCyan, binary.LittleEndian.Uint64(data[i+j:i+j+8]), ColorReset)
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

func (q *QemuDbg) resolveSymbols(cmd string) (string, error) {
	resolver := NewQemuSymbolResolver(q)
	return ResolveSymbolsInCommand(cmd, resolver)
}

func (q *QemuDbg) Interactive() {
	// Set up signal handler for Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	defer signal.Stop(sigChan)

	// Handle SIGINT in background - interrupt running QEMU target
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
