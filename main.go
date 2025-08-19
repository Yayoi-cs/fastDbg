package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	fn := flag.String("f", "", "filename")
	pid := flag.Int("p", 0, "process id")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if (*fn == "" && *pid == 0) || (*fn != "" && *pid != 0) {
		fmt.Fprintf(os.Stderr, "Invalid arguments\n")
		flag.Usage()
		os.Exit(1)
	}

	if *fn != "" {
		mainDbger.path = *fn
		mainDbger.Interactive()
	}

	if *pid != 0 {
		dbger, err := Attach(*pid)
		mainDbger = *dbger
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error attaching pid %d: %s\n", *pid, err)
			os.Exit(1)
		}
		mainDbger.Interactive()
	}

	return
}
