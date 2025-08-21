package main

import (
	"fmt"
	"github.com/manifoldco/promptui"
)

/*
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

int test(int pid) {
    struct user_regs_struct regs;

    printf("Attempting to get registers for PID %d...\n", pid);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        printf("PTRACE_GETREGS failed: errno=%d (%s)\n", errno, strerror(errno));
        return errno;
    }

    printf("SUCCESS: Got registers from C ptrace!\n");
    printf("Registers (directly from C):\n");
    printf("RAX: 0x%016llx  RBX: 0x%016llx  RCX: 0x%016llx  RDX: 0x%016llx\n",
           regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("RSI: 0x%016llx  RDI: 0x%016llx  RBP: 0x%016llx  RSP: 0x%016llx\n",
           regs.rsi, regs.rdi, regs.rbp, regs.rsp);
    printf("RIP: 0x%016llx  EFLAGS: 0x%016llx\n", regs.rip, regs.eflags);
    printf("R8:  0x%016llx  R9:  0x%016llx  R10: 0x%016llx  R11: 0x%016llx\n",
           regs.r8, regs.r9, regs.r10, regs.r11);
    printf("R12: 0x%016llx  R13: 0x%016llx  R14: 0x%016llx  R15: 0x%016llx\n",
           regs.r12, regs.r13, regs.r14, regs.r15);
    printf("CS: 0x%llx  SS: 0x%llx  DS: 0x%llx  ES: 0x%llx  FS: 0x%llx  GS: 0x%llx\n",
           regs.cs, regs.ss, regs.ds, regs.es, regs.fs, regs.gs);

    return 0;
}
*/
import "C"

func (dbger *TypeDbg) Interactive() {
	dbger.LoadSymbolsFromELF()
	prev := ""

	templates := &promptui.PromptTemplates{
		Prompt:  "{{ . }}",
		Valid:   "{{ . }}",
		Invalid: "{{ . }}",
		Success: "{{ . }}",
	}
	for {
		//for _ = range 5 {
		//	tmpRip, err := dbger.GetRip()
		//	if err == nil {
		//		dbger.rip = tmpRip
		//		break
		//	}
		//}

		//ok := func(rip uint64) bool {
		//	for _, b := range Bps {
		//		if b.addr == uintptr(rip-1) && b.isEnable {
		//			return true
		//		}
		//	}
		//	return false
		//}(dbger.rip)

		//if ok {
		//	dbger.rip--
		//}

		var label string
		if !dbger.isStart {
			label = "[fastDbg]$ "
		} else {
			label = fmt.Sprintf("[%s%x%s]$ ", ColorCyan, dbger.rip, ColorReset)
		}

		prompt := promptui.Prompt{
			Label:     label,
			Templates: templates,
		}

		req, err := prompt.Run()
		if err != nil {
			if err == promptui.ErrInterrupt {
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

		if req == "q" || req == "exit" {
			break
		}
		fmt.Println("IsStopped: ", dbger.isStopped())
		prev = req
		err = dbger.cmdExec(req)

		if err != nil {
			LogError(err.Error())
		}
	}
}
