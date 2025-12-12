package main

import (
	"fastDbg/qemu"
	"flag"
	"fmt"
	"github.com/common-nighthawk/go-figure"
	"os"
)

func main() {
	fn := flag.String("f", "", "filename for userland debugging")
	pid := flag.Int("p", 0, "process id for attaching")
	qemuMode := flag.Bool("qemu", false, "enable QEMU kernel debugging mode")
	qemuHost := flag.String("qemu-host", "localhost", "QEMU GDB server host")
	qemuPort := flag.Int("qemu-port", 12345, "QEMU GDB server port")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nUserland Debugging:\n")
		fmt.Fprintf(os.Stderr, "  -f <file>    Debug executable file\n")
		fmt.Fprintf(os.Stderr, "  -p <pid>     Attach to running process\n")
		fmt.Fprintf(os.Stderr, "\nKernel Debugging (QEMU):\n")
		fmt.Fprintf(os.Stderr, "  -qemu              Enable QEMU kernel debugging\n")
		fmt.Fprintf(os.Stderr, "  -qemu-host <host>  QEMU GDB server host (default: localhost)\n")
		fmt.Fprintf(os.Stderr, "  -qemu-port <port>  QEMU GDB server port (default: 12345)\n")
	}

	flag.Parse()

	fig := figure.NewFigure("fastDbg", "isometric1", true)
	fig.Print()

	if *qemuMode {
		qdbg, err := qemu.Connect(*qemuHost, *qemuPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to QEMU: %v\n", err)
			os.Exit(1)
		}
		defer qdbg.Close()

		qdbg.Interactive()
		return
	}

	if (*fn == "" && *pid == 0) || (*fn != "" && *pid != 0) {
		fmt.Fprintf(os.Stderr, "Error: Must specify either -f <file> OR -p <pid> OR -qemu\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *fn != "" {
		mainDbger.path = *fn
		mainDbger.Interactive(false)
	}

	if *pid != 0 {
		dbger, err := Attach(*pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error attaching pid %d: %s\n", *pid, err)
			os.Exit(1)
		}
		mainDbger = *dbger

		mainDbger.Interactive(true)
	}

	return
}
