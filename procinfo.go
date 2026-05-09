package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func (dbger *TypeDbg) cmdProcInfo(_ interface{}) error {
	if !dbger.isStart || !dbger.isProcessAlive() {
		return errors.New("debuggee has not started or is not alive")
	}
	pid := dbger.pid

	hLine("Process Information")
	piPrintMain(pid)

	hLine("Parent Process Information")
	piPrintParent(pid)

	hLine("Child Process Information")
	piPrintChildren(pid)

	hLine("Thread Information")
	piPrintThreads(pid)

	hLine("Namespace Information")
	piPrintNamespaces(pid)

	hLine("Pid Namespace Information")
	piPrintPidNS(pid)

	hLine("User Namespace Information")
	piPrintUserNS(pid)

	hLine("File Descriptors")
	piPrintFDs(pid)

	hLine("Network Connections")
	piPrintNetwork(pid)

	hLineRaw()
	return nil
}

const piLabelWidth = 33

func piLine(indent int, label, value string) {
	pad := strings.Repeat(" ", indent)
	width := piLabelWidth - indent
	fmt.Printf("%s%-*s ->  %s\n", pad, width, label, value)
}

func readProcLink(pid int, name string) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return ""
	}
	return target
}

func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	s := strings.TrimRight(string(data), "\x00")
	return strings.ReplaceAll(s, "\x00", " ")
}

func readProcStatus(pid int) map[string]string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		ln := s.Text()
		if i := strings.IndexByte(ln, ':'); i > 0 {
			out[ln[:i]] = strings.TrimSpace(ln[i+1:])
		}
	}
	return out
}

func readProcStat(pid int) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil
	}
	s := string(data)
	end := strings.LastIndex(s, ")")
	if end < 0 {
		return nil
	}
	first := strings.IndexByte(s, ' ')
	if first < 0 || first >= end {
		return nil
	}
	pidStr := s[:first]
	comm := s[first+2 : end]
	rest := strings.Fields(s[end+1:])
	fields := make([]string, 0, 2+len(rest))
	fields = append(fields, pidStr, comm)
	fields = append(fields, rest...)
	return fields
}

func piPrintMain(pid int) {
	status := readProcStatus(pid)
	exe := readProcLink(pid, "exe")
	if exe == "" {
		exe = "Not found"
	}
	cmdline := readProcCmdline(pid)
	cwd := readProcLink(pid, "cwd")
	root := readProcLink(pid, "root")

	piLine(0, "PID", fmt.Sprintf("%s%d%s", ColorCyan, pid, ColorReset))
	piLine(2, "Executable", fmt.Sprintf("'%s%s%s'", ColorCyan, exe, ColorReset))
	piLine(2, "Command Line", fmt.Sprintf("'%s%s%s'", ColorCyan, cmdline, ColorReset))
	piLine(2, "Current Working Directory", fmt.Sprintf("'%s%s%s'", ColorCyan, cwd, ColorReset))
	piLine(2, "Root Directory", fmt.Sprintf("'%s%s%s'", ColorCyan, root, ColorReset))

	if uid := status["Uid"]; uid != "" {
		p := strings.Fields(uid)
		if len(p) == 4 {
			piLine(2, "RUID:EUID:SavedUID:FSUID",
				fmt.Sprintf("%s%s : %s : %s : %s%s", ColorCyan, p[0], p[1], p[2], p[3], ColorReset))
		}
	}
	if gid := status["Gid"]; gid != "" {
		p := strings.Fields(gid)
		if len(p) == 4 {
			piLine(2, "RGID:EGID:SavedGID:FSGID",
				fmt.Sprintf("%s%s : %s : %s : %s%s", ColorCyan, p[0], p[1], p[2], p[3], ColorReset))
		}
	}
	if sec := status["Seccomp"]; sec != "" {
		mode, _ := strconv.Atoi(sec)
		modeStr := []string{"Disabled", "Strict", "Filter"}[0]
		switch mode {
		case 1:
			modeStr = "Strict"
		case 2:
			modeStr = "Filter"
		}
		piLine(2, "Seccomp Mode", fmt.Sprintf("%s%d (%s)%s", ColorCyan, mode, modeStr, ColorReset))
	}
	stat := readProcStat(pid)
	if len(stat) < 8 {
		return
	}
	pgrp, _ := strconv.Atoi(stat[4])
	sid, _ := strconv.Atoi(stat[5])
	ttyNr, _ := strconv.Atoi(stat[6])
	tpgid, _ := strconv.Atoi(stat[7])

	piLine(0, "Process Group ID", fmt.Sprintf("%s%d%s", ColorCyan, pgrp, ColorReset))
	piLine(2, "Executable", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcLinkOr(pgrp, "exe", "Not found"), ColorReset))
	piLine(2, "Command Line", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcCmdline(pgrp), ColorReset))

	piLine(0, "Session ID", fmt.Sprintf("%s%d%s", ColorCyan, sid, ColorReset))
	piLine(2, "Executable", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcLinkOr(sid, "exe", "Not found"), ColorReset))
	piLine(2, "Command Line", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcCmdline(sid), ColorReset))

	piLine(0, "TTY Process Group ID", fmt.Sprintf("%s%d%s", ColorCyan, tpgid, ColorReset))
	piLine(2, "Executable", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcLinkOr(tpgid, "exe", "Not found"), ColorReset))
	piLine(2, "Command Line", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcCmdline(tpgid), ColorReset))
	if ttyNr != 0 {
		major := (ttyNr >> 8) & 0xff
		minor := (ttyNr & 0xff) | ((ttyNr >> 12) << 8)
		dev := decodeTTY(major, minor)
		piLine(2, "TTY Device Number", fmt.Sprintf("%s%d ('%s')%s", ColorCyan, ttyNr, dev, ColorReset))
	}
}

func readProcLinkOr(pid int, name, fallback string) string {
	v := readProcLink(pid, name)
	if v == "" {
		return fallback
	}
	return v
}

func decodeTTY(major, minor int) string {
	if major == 136 {
		return fmt.Sprintf("/dev/pts/%d", minor)
	}
	if major == 4 {
		return fmt.Sprintf("/dev/tty%d", minor)
	}
	if major == 5 && minor == 0 {
		return "/dev/tty"
	}
	return fmt.Sprintf("char-major-%d:%d", major, minor)
}

func piPrintParent(pid int) {
	stat := readProcStat(pid)
	if len(stat) < 4 {
		return
	}
	ppid, _ := strconv.Atoi(stat[3])
	if ppid <= 0 {
		piLine(0, "Parent PID", "<none>")
		return
	}
	piLine(0, "Parent PID", fmt.Sprintf("%s%d%s", ColorCyan, ppid, ColorReset))
	piLine(2, "Executable", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcLinkOr(ppid, "exe", "Not found"), ColorReset))
	piLine(2, "Command Line", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcCmdline(ppid), ColorReset))
}

func piPrintChildren(pid int) {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		fmt.Println("  <unable to read task dir>")
		return
	}
	seen := map[int]bool{}
	var children []int
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "children"))
		if err != nil {
			continue
		}
		for _, tok := range strings.Fields(string(data)) {
			c, err := strconv.Atoi(tok)
			if err != nil || seen[c] {
				continue
			}
			seen[c] = true
			children = append(children, c)
		}
	}
	if len(children) == 0 {
		fmt.Println("  No children")
		return
	}
	sort.Ints(children)
	for i, c := range children {
		piLine(0, fmt.Sprintf("Child %d PID", i+1), fmt.Sprintf("%s%d%s", ColorCyan, c, ColorReset))
		piLine(2, "Executable", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcLinkOr(c, "exe", "Not found"), ColorReset))
		piLine(2, "Command Line", fmt.Sprintf("'%s%s%s'", ColorCyan, readProcCmdline(c), ColorReset))
	}
}

func piPrintThreads(pid int) {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		fmt.Println("  <unable to read task dir>")
		return
	}
	var tids []int
	for _, e := range entries {
		t, err := strconv.Atoi(e.Name())
		if err == nil {
			tids = append(tids, t)
		}
	}
	sort.Ints(tids)
	status := readProcStatus(pid)
	tgid := status["Tgid"]
	piLine(0, "Num of Threads", fmt.Sprintf("%s%d%s", ColorCyan, len(tids), ColorReset))
	piLine(0, "Thread Group ID", fmt.Sprintf("%s%s%s", ColorCyan, tgid, ColorReset))
	tidStrs := make([]string, len(tids))
	for i, t := range tids {
		tidStrs[i] = strconv.Itoa(t)
	}
	piLine(0, "Thread ID List", fmt.Sprintf("%s[%s]%s", ColorCyan, strings.Join(tidStrs, ", "), ColorReset))
}

func piPrintNamespaces(pid int) {
	nsNames := []string{"cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"}
	for _, ns := range nsNames {
		mine := readProcLink(pid, "ns/"+ns)
		root := readProcLink(1, "ns/"+ns)
		separated := mine != "" && root != "" && mine != root
		val := "False"
		if separated {
			val = "True"
		}
		piLine(0, fmt.Sprintf("%s namespace separation", strings.ToUpper(ns)),
			fmt.Sprintf("%s%s%s", ColorCyan, val, ColorReset))
	}
}

func piPrintPidNS(pid int) {
	status := readProcStatus(pid)
	nspid := status["NSpid"]
	if nspid == "" || nspid == status["Pid"] {
		fmt.Println("  No pid namespace")
		return
	}
	piLine(0, "Namespaced PID", fmt.Sprintf("%s%s%s", ColorCyan, nspid, ColorReset))
}

func piPrintUserNS(pid int) {
	for _, name := range []string{"uid_map", "gid_map"} {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
		if err != nil || len(data) == 0 {
			continue
		}
		for _, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			f := strings.Fields(ln)
			if len(f) != 3 {
				continue
			}
			inside, _ := strconv.Atoi(f[0])
			outside, _ := strconv.Atoi(f[1])
			rng, _ := strconv.Atoi(f[2])
			label := strings.ToUpper(name[:3]) + "_MAP [NameSpace:Host:Range]"
			piLine(0, label, fmt.Sprintf("%s[0x%x : 0x%x : 0x%x]%s",
				ColorCyan, inside, outside, rng, ColorReset))
		}
	}
}

func piPrintFDs(pid int) {
	status := readProcStatus(pid)
	if v := status["FDSize"]; v != "" {
		piLine(0, "Num of FD slots", fmt.Sprintf("%s%s%s", ColorCyan, v, ColorReset))
	}
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		fmt.Println("  <unable to read fd dir>")
		return
	}
	type fdEntry struct {
		num    int
		target string
	}
	var fds []fdEntry
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		t, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		fds = append(fds, fdEntry{n, t})
	}
	sort.Slice(fds, func(i, j int) bool { return fds[i].num < fds[j].num })
	for _, fd := range fds {
		left := fmt.Sprintf("/proc/%d/fd/%d", pid, fd.num)
		fmt.Printf("%-*s ->  %s%s%s\n", piLabelWidth, left, ColorCyan, fd.target, ColorReset)
	}
}

func piPrintNetwork(pid int) {
	socketInodes := socketFDs(pid)
	if len(socketInodes) == 0 {
		fmt.Println("  No open connections")
		return
	}

	conns := map[uint64]string{}
	for _, fam := range []struct {
		path, label string
		v6          bool
	}{
		{fmt.Sprintf("/proc/%d/net/tcp", pid), "TCP", false},
		{fmt.Sprintf("/proc/%d/net/tcp6", pid), "TCP6", true},
		{fmt.Sprintf("/proc/%d/net/udp", pid), "UDP", false},
		{fmt.Sprintf("/proc/%d/net/udp6", pid), "UDP6", true},
	} {
		parseProcNet(fam.path, fam.label, fam.v6, conns)
	}

	any := false
	for inode := range socketInodes {
		if desc, ok := conns[inode]; ok {
			any = true
			piLine(0, fmt.Sprintf("inode=%d", inode), fmt.Sprintf("%s%s%s", ColorCyan, desc, ColorReset))
		}
	}
	if !any {
		fmt.Println("  No open connections")
	}
}

func socketFDs(pid int) map[uint64]bool {
	out := map[uint64]bool{}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return out
	}
	for _, e := range entries {
		t, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, e.Name()))
		if err != nil {
			continue
		}
		if !strings.HasPrefix(t, "socket:[") {
			continue
		}
		raw := strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")
		ino, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			continue
		}
		out[ino] = true
	}
	return out
}

func parseProcNet(path, label string, v6 bool, conns map[uint64]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		if first {
			first = false
			continue
		}
		fl := strings.Fields(s.Text())
		if len(fl) < 10 {
			continue
		}
		local := decodeAddr(fl[1], v6)
		remote := decodeAddr(fl[2], v6)
		state := tcpState(fl[3])
		ino, err := strconv.ParseUint(fl[9], 10, 64)
		if err != nil {
			continue
		}
		conns[ino] = fmt.Sprintf("%s %s -> %s (%s)", label, local, remote, state)
	}
}

func decodeAddr(s string, v6 bool) string {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s
	}
	port, _ := strconv.ParseUint(parts[1], 16, 16)
	if v6 {
		raw, err := hex.DecodeString(parts[0])
		if err != nil || len(raw) != 16 {
			return s
		}
		out := make([]byte, 16)
		for i := 0; i < 16; i += 4 {
			out[i+0] = raw[i+3]
			out[i+1] = raw[i+2]
			out[i+2] = raw[i+1]
			out[i+3] = raw[i+0]
		}
		return fmt.Sprintf("[%s]:%d", net.IP(out).String(), port)
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil || len(raw) != 4 {
		return s
	}
	ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

func tcpState(hexState string) string {
	st, err := strconv.ParseUint(hexState, 16, 8)
	if err != nil {
		return hexState
	}
	names := []string{
		"UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
		"FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK",
		"LISTEN", "CLOSING", "NEW_SYN_RECV",
	}
	if int(st) < len(names) {
		return names[st]
	}
	return fmt.Sprintf("STATE_%d", st)
}
