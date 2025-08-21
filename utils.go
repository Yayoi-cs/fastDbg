package main

import (
	"fmt"
	"golang.org/x/term"
	"os"
	"strings"
)

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

func hLine(msg string) {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		w, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err == nil && w > 0 {
			fmt.Printf(strings.Repeat("-", (w-len(msg)-2)/2) + "[" + msg + "]" + strings.Repeat("-", (w-len(msg)-2)/2) + "\n")
			return
		}
	}
	fmt.Printf("[" + msg + "]")
}
