package main

/*
#include <stdint.h>
#include <string.h>

struct xsave_header {
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    uint64_t reserved[6];
};

struct i387_fxsave_struct {
    uint16_t cwd;
    uint16_t swd;
    uint16_t twd;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    uint32_t st_space[32];
    uint32_t xmm_space[64];
    uint32_t padding[24];
};

struct xsave_struct {
    struct i387_fxsave_struct i387;
    struct xsave_header header;
};
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"math"
	"unsafe"
)

const (
	NT_X86_XSTATE = 0x202
)

// XSAVE state component bits
const (
	XSTATE_FP        = 0x1
	XSTATE_SSE       = 0x2
	XSTATE_YMM       = 0x4
	XSTATE_BNDREGS   = 0x8
	XSTATE_BNDCSR    = 0x10
	XSTATE_OPMASK    = 0x20
	XSTATE_ZMM_Hi256 = 0x40
	XSTATE_Hi16_ZMM  = 0x80
)

func (dbger *TypeDbg) getExtendedRegs() ([]byte, error) {
	buf := make([]byte, 4096)

	iov := unix.Iovec{
		Base: &buf[0],
		Len:  uint64(len(buf)),
	}

	err := doSyscallErr(dbger.rpc, func() error {
		_, _, errno := unix.Syscall6(
			unix.SYS_PTRACE,
			unix.PTRACE_GETREGSET,
			uintptr(dbger.pid),
			uintptr(NT_X86_XSTATE),
			uintptr(unsafe.Pointer(&iov)),
			0, 0,
		)
		if errno != 0 {
			return errno
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return buf[:iov.Len], nil
}

func printXMMRegister(name string, data []byte) {
	if len(data) != 16 {
		return
	}

	fmt.Printf("%-6s: ", name)
	for i := 15; i >= 0; i-- {
		fmt.Printf("%02x", data[i])
		if i == 8 {
			fmt.Print(" ")
		}
	}

	fmt.Print(" | ")

	f64_0 := math.Float64frombits(binary.LittleEndian.Uint64(data[0:8]))
	f64_1 := math.Float64frombits(binary.LittleEndian.Uint64(data[8:16]))
	fmt.Printf("f64:[%.6f %.6f]", f64_0, f64_1)

	fmt.Println()
}

func printYMMRegister(name string, lowData, highData []byte) {
	if len(lowData) != 16 || len(highData) != 16 {
		return
	}

	fmt.Printf("%-6s: ", name)

	for i := 15; i >= 0; i-- {
		fmt.Printf("%02x", highData[i])
	}
	fmt.Print(" ")

	for i := 15; i >= 0; i-- {
		fmt.Printf("%02x", lowData[i])
	}

	fmt.Println()
}

func (dbger *TypeDbg) cmdSIMD(a interface{}) error {
	if !dbger.isStart {
		return fmt.Errorf("debuggee has not started")
	}

	if !dbger.isProcessAlive() {
		return fmt.Errorf("process is not alive")
	}

	extRegs, err := dbger.getExtendedRegs()
	if err != nil {
		return fmt.Errorf("failed to get extended registers: %v", err)
	}

	if len(extRegs) < 512 {
		return fmt.Errorf("invalid XSAVE buffer size: %d bytes", len(extRegs))
	}

	// Parse XSAVE structure
	xsave := (*C.struct_xsave_struct)(unsafe.Pointer(&extRegs[0]))
	xstateBv := uint64(xsave.header.xstate_bv)

	// Display SSE status register
	mxcsr := uint32(xsave.i387.mxcsr)
	fmt.Printf("MXCSR: %s0x%08x%s", ColorCyan, mxcsr, ColorReset)
	fmt.Printf(" [")
	if mxcsr&0x1 != 0 {
		fmt.Print("IE ")
	}
	if mxcsr&0x2 != 0 {
		fmt.Print("DE ")
	}
	if mxcsr&0x4 != 0 {
		fmt.Print("ZE ")
	}
	if mxcsr&0x8 != 0 {
		fmt.Print("OE ")
	}
	if mxcsr&0x10 != 0 {
		fmt.Print("UE ")
	}
	if mxcsr&0x20 != 0 {
		fmt.Print("PE ")
	}
	fmt.Printf("] RC:%d FTZ:%d DAZ:%d\n",
		(mxcsr>>13)&0x3, (mxcsr>>15)&0x1, (mxcsr>>6)&0x1)

	fmt.Printf("XSTATE_BV: %s0x%016x%s ", ColorCyan, xstateBv, ColorReset)
	fmt.Printf("[")
	if xstateBv&XSTATE_FP != 0 {
		fmt.Print("x87 ")
	}
	if xstateBv&XSTATE_SSE != 0 {
		fmt.Print("SSE ")
	}
	if xstateBv&XSTATE_YMM != 0 {
		fmt.Print("AVX ")
	}
	if xstateBv&XSTATE_OPMASK != 0 {
		fmt.Print("AVX512_OPMASK ")
	}
	if xstateBv&XSTATE_ZMM_Hi256 != 0 {
		fmt.Print("AVX512_ZMM_Hi256 ")
	}
	if xstateBv&XSTATE_Hi16_ZMM != 0 {
		fmt.Print("AVX512_Hi16_ZMM ")
	}
	fmt.Printf("]\n\n")

	hLine("XMM Registers (SSE - 128 bit)")
	for i := 0; i < 16; i++ {
		xmmData := make([]byte, 16)
		// Copy XMM register data (16 bytes)
		for j := 0; j < 16; j++ {
			xmmData[j] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&xsave.i387.xmm_space[0])) + uintptr(i*16+j)))
		}
		printXMMRegister(fmt.Sprintf("XMM%d", i), xmmData)
	}

	if xstateBv&XSTATE_YMM != 0 {
		fmt.Println()
		hLine("YMM Registers (AVX - 256 bit)")

		ymmhOffset := 576

		if len(extRegs) >= ymmhOffset+256 {
			for i := 0; i < 16; i++ {
				xmmData := make([]byte, 16)
				for j := 0; j < 16; j++ {
					xmmData[j] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&xsave.i387.xmm_space[0])) + uintptr(i*16+j)))
				}

				ymmhData := make([]byte, 16)
				for j := 0; j < 16; j++ {
					ymmhData[j] = extRegs[ymmhOffset+i*16+j]
				}

				printYMMRegister(fmt.Sprintf("YMM%d", i), xmmData, ymmhData)
			}
		}
	}

	fmt.Println()
	hLine("x87 FPU Registers")
	fmt.Printf("FCW: %s0x%04x%s  FSW: %s0x%04x%s  FTW: %s0x%04x%s  FOP: %s0x%04x%s\n",
		ColorCyan, xsave.i387.cwd, ColorReset,
		ColorCyan, xsave.i387.swd, ColorReset,
		ColorCyan, xsave.i387.twd, ColorReset,
		ColorCyan, xsave.i387.fop, ColorReset)
	fmt.Printf("FIP: %s0x%016x%s  FDP: %s0x%016x%s\n",
		ColorCyan, xsave.i387.rip, ColorReset,
		ColorCyan, xsave.i387.rdp, ColorReset)

	fmt.Println()
	for i := 0; i < 8; i++ {
		stData := make([]byte, 16)
		for j := 0; j < 16; j++ {
			stData[j] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&xsave.i387.st_space[0])) + uintptr(i*16+j)))
		}

		fmt.Printf("ST(%d)  : ", i)
		for j := 15; j >= 0; j-- {
			fmt.Printf("%02x", stData[j])
			if j == 8 {
				fmt.Print(" ")
			}
		}
		fmt.Println()
	}

	return nil
}
