//go:build ignore
// +build ignore

package main

import (
	"fastDbg/qemu"
	"flag"
	"log"
)

func main() {
	host := flag.String("host", "localhost", "QEMU GDB server host")
	port := flag.Int("port", 1234, "QEMU GDB server port")
	flag.Parse()

	log.Printf("Connecting to QEMU at %s:%d...\n", *host, *port)
	log.Println("Make sure QEMU is running with -s -S flags")
	log.Println("Example: qemu-system-x86_64 -kernel vmlinuz -s -S")
	log.Println()

	err := qemu.RunQemuDebugger(*host, *port)
	if err != nil {
		log.Fatal(err)
	}
}
