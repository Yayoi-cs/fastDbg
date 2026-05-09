package qemu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type QemuDbg struct {
	conn    net.Conn
	host    string
	port    int
	arch    int
	isStart bool

	regLayout *RegLayout

	// rxBuf carries bytes read from the socket that haven't been consumed yet.
	// TCP can deliver multiple GDB packets in a single read (e.g. an `O...`
	// stream packet bundled with its trailing `OK`), so we keep a persistent
	// buffer instead of discarding whatever recvPacket didn't return.
	rxBuf []byte
}

func Connect(host string, port int) (*QemuDbg, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", addr, err)
	}

	dbg := &QemuDbg{
		conn:    conn,
		host:    host,
		port:    port,
		arch:    64,
		isStart: true,
	}
	_, err = conn.Write([]byte("+"))
	if err != nil {
		conn.Close()
		return nil, err
	}

	fmt.Printf("Connected to QEMU GDB stub at %s\n", addr)

	dbg.autoDetect()

	return dbg, nil
}

// autoDetect probes the connected QEMU stub for capabilities. We negotiate
// supported features (so QEMU emits the full target description with control
// registers), then fetch target.xml and any included files to build a
// register-name → (regnum, offset, size) map. This is what makes CR3 access
// stable across QEMU versions instead of guessing offsets in the `g` blob.
//
// If the stub is too old to expose cr3 in target.xml (pre-QEMU 8.0), we just
// log it; GetCR3 will fall back to parsing `monitor info registers`.
func (q *QemuDbg) autoDetect() {
	if _, err := q.readResponse("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386"); err != nil {
		fmt.Printf("warn: qSupported handshake failed: %v\n", err)
	}

	layout, err := q.loadRegLayout()
	if err != nil {
		fmt.Printf("warn: target description discovery failed (%v); CR3 will use monitor fallback\n", err)
		return
	}
	q.regLayout = layout

	if cr3, ok := layout.ByName["cr3"]; ok {
		fmt.Printf("Auto-detected register layout: %d registers, cr3 at regnum=%d offset=%d\n",
			len(layout.ByName), cr3.RegNum, cr3.Offset)
	} else {
		fmt.Printf("Auto-detected register layout: %d registers; cr3 not exposed by this QEMU (will use monitor fallback)\n",
			len(layout.ByName))
	}
}

func (q *QemuDbg) Close() error {
	if q.conn != nil {
		q.sendPacket("D")
		return q.conn.Close()
	}
	return nil
}

func (q *QemuDbg) sendPacket(data string) error {
	checksum := byte(0)
	for i := 0; i < len(data); i++ {
		checksum += data[i]
	}
	packet := fmt.Sprintf("$%s#%02x", data, checksum)

	for retry := 0; retry < 3; retry++ {
		_, err := q.conn.Write([]byte(packet))
		if err != nil {
			return err
		}

		var ack byte
		if len(q.rxBuf) > 0 {
			ack = q.rxBuf[0]
			q.rxBuf = q.rxBuf[1:]
		} else {
			q.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			ackBuf := make([]byte, 1)
			n, err := q.conn.Read(ackBuf)
			q.conn.SetReadDeadline(time.Time{})
			if err != nil {
				if retry < 2 {
					continue
				}
				return fmt.Errorf("failed to read ack: %v", err)
			}
			if n == 0 {
				continue
			}
			ack = ackBuf[0]
		}

		if ack == '+' {
			return nil
		}
		if ack == '-' {
			continue
		}
		// Not an ack byte (e.g. a `$` from a piggy-backed response packet);
		// push it back so recvPacket can pick it up.
		q.rxBuf = append([]byte{ack}, q.rxBuf...)
		return nil
	}

	return fmt.Errorf("failed to send packet after 3 retries")
}

func (q *QemuDbg) recvPacket() (string, error) {
	q.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer q.conn.SetReadDeadline(time.Time{})

	tmp := make([]byte, 4096)

	for {
		startIdx := bytes.IndexByte(q.rxBuf, '$')
		if startIdx >= 0 {
			hashIdx := bytes.IndexByte(q.rxBuf[startIdx+1:], '#')
			if hashIdx >= 0 {
				hashIdx += startIdx + 1
				if hashIdx+2 < len(q.rxBuf) {
					data := string(q.rxBuf[startIdx+1 : hashIdx])
					checksumStr := string(q.rxBuf[hashIdx+1 : hashIdx+3])

					expected := byte(0)
					for i := 0; i < len(data); i++ {
						expected += data[i]
					}
					var received byte
					fmt.Sscanf(checksumStr, "%02x", &received)

					q.rxBuf = q.rxBuf[hashIdx+3:]

					if expected == received {
						_, _ = q.conn.Write([]byte("+"))
						return data, nil
					}
					_, _ = q.conn.Write([]byte("-"))
					return "", fmt.Errorf("checksum mismatch")
				}
			}
		}

		n, err := q.conn.Read(tmp)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		q.rxBuf = append(q.rxBuf, tmp[:n]...)
	}
}

func (q *QemuDbg) readResponse(cmd string) (string, error) {
	if err := q.sendPacket(cmd); err != nil {
		return "", err
	}
	return q.recvPacket()
}

func (q *QemuDbg) GetMemory(size uint, addr uintptr) ([]byte, error) {
	cmd := fmt.Sprintf("m%x,%x", addr, size)
	resp, err := q.readResponse(cmd)
	if err != nil {
		return nil, err
	}

	if resp == "" {
		return nil, errors.New("failed to read memory")
	}
	if resp[0] == 'E' {
		return nil, fmt.Errorf("memory read at 0x%x failed: %s", addr, resp)
	}

	data, err := hex.DecodeString(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode memory: %v", err)
	}

	return data, nil
}

func (q *QemuDbg) SetMemory(data []byte, addr uintptr) error {
	hexData := hex.EncodeToString(data)
	cmd := fmt.Sprintf("M%x,%x:%s", addr, len(data), hexData)
	resp, err := q.readResponse(cmd)
	if err != nil {
		return err
	}

	if resp != "OK" {
		return fmt.Errorf("failed to write memory: %s", resp)
	}

	return nil
}

func (q *QemuDbg) Continue() error {
	return q.sendPacket("c")
}

func (q *QemuDbg) Interrupt() error {
	// Send Ctrl+C (0x03) to interrupt the running target
	// This is the GDB remote protocol way to interrupt execution
	_, err := q.conn.Write([]byte{0x03})
	if err != nil {
		return fmt.Errorf("failed to send interrupt: %v", err)
	}

	// Read the stop response
	_, err = q.recvPacket()
	if err != nil {
		return fmt.Errorf("failed to receive interrupt response: %v", err)
	}

	return nil
}

func (q *QemuDbg) Step() error {
	if err := q.sendPacket("s"); err != nil {
		return err
	}
	_, err := q.recvPacket()
	return err
}

type Regs struct {
	Rax    uint64
	Rbx    uint64
	Rcx    uint64
	Rdx    uint64
	Rsi    uint64
	Rdi    uint64
	Rbp    uint64
	Rsp    uint64
	R8     uint64
	R9     uint64
	R10    uint64
	R11    uint64
	R12    uint64
	R13    uint64
	R14    uint64
	R15    uint64
	Rip    uint64
	Eflags uint64
	Cs     uint32
	Ss     uint32
	Ds     uint32
	Es     uint32
	Fs     uint32
	Gs     uint32
}

// GetRegs reads the full register blob (`g` packet) and slices out the GP /
// segment registers. When the target description has been auto-detected at
// connect time, byte offsets come from there — so the layout stays correct
// across QEMU versions that reorder or insert registers. If no layout was
// discovered (e.g. very old QEMU without qXfer:features support), we fall
// back to the historical fixed offsets that match QEMU's traditional x86_64
// `g` layout.
func (q *QemuDbg) GetRegs() (*Regs, error) {
	resp, err := q.readResponse("g")
	if err != nil {
		return nil, err
	}

	resp = strings.TrimSpace(resp)

	data, err := hex.DecodeString(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode registers: %v (response: %s)", err, resp[:min(len(resp), 50)])
	}

	regs := &Regs{}

	if q.regLayout != nil {
		regs.Rax = sliceReg64(data, q.regLayout, "rax")
		regs.Rbx = sliceReg64(data, q.regLayout, "rbx")
		regs.Rcx = sliceReg64(data, q.regLayout, "rcx")
		regs.Rdx = sliceReg64(data, q.regLayout, "rdx")
		regs.Rsi = sliceReg64(data, q.regLayout, "rsi")
		regs.Rdi = sliceReg64(data, q.regLayout, "rdi")
		regs.Rbp = sliceReg64(data, q.regLayout, "rbp")
		regs.Rsp = sliceReg64(data, q.regLayout, "rsp")
		regs.R8 = sliceReg64(data, q.regLayout, "r8")
		regs.R9 = sliceReg64(data, q.regLayout, "r9")
		regs.R10 = sliceReg64(data, q.regLayout, "r10")
		regs.R11 = sliceReg64(data, q.regLayout, "r11")
		regs.R12 = sliceReg64(data, q.regLayout, "r12")
		regs.R13 = sliceReg64(data, q.regLayout, "r13")
		regs.R14 = sliceReg64(data, q.regLayout, "r14")
		regs.R15 = sliceReg64(data, q.regLayout, "r15")
		regs.Rip = sliceReg64(data, q.regLayout, "rip")
		regs.Eflags = sliceReg64(data, q.regLayout, "eflags")
		regs.Cs = uint32(sliceReg64(data, q.regLayout, "cs"))
		regs.Ss = uint32(sliceReg64(data, q.regLayout, "ss"))
		regs.Ds = uint32(sliceReg64(data, q.regLayout, "ds"))
		regs.Es = uint32(sliceReg64(data, q.regLayout, "es"))
		regs.Fs = uint32(sliceReg64(data, q.regLayout, "fs"))
		regs.Gs = uint32(sliceReg64(data, q.regLayout, "gs"))
		return regs, nil
	}

	if len(data) < 8*17 {
		return nil, fmt.Errorf("insufficient register data: got %d bytes, need at least %d", len(data), 8*17)
	}

	regs.Rax = binary.LittleEndian.Uint64(data[0:8])
	regs.Rbx = binary.LittleEndian.Uint64(data[8:16])
	regs.Rcx = binary.LittleEndian.Uint64(data[16:24])
	regs.Rdx = binary.LittleEndian.Uint64(data[24:32])
	regs.Rsi = binary.LittleEndian.Uint64(data[32:40])
	regs.Rdi = binary.LittleEndian.Uint64(data[40:48])
	regs.Rbp = binary.LittleEndian.Uint64(data[48:56])
	regs.Rsp = binary.LittleEndian.Uint64(data[56:64])
	regs.R8 = binary.LittleEndian.Uint64(data[64:72])
	regs.R9 = binary.LittleEndian.Uint64(data[72:80])
	regs.R10 = binary.LittleEndian.Uint64(data[80:88])
	regs.R11 = binary.LittleEndian.Uint64(data[88:96])
	regs.R12 = binary.LittleEndian.Uint64(data[96:104])
	regs.R13 = binary.LittleEndian.Uint64(data[104:112])
	regs.R14 = binary.LittleEndian.Uint64(data[112:120])
	regs.R15 = binary.LittleEndian.Uint64(data[120:128])
	regs.Rip = binary.LittleEndian.Uint64(data[128:136])
	regs.Eflags = binary.LittleEndian.Uint64(data[136:144])

	if len(data) >= 168 {
		regs.Cs = binary.LittleEndian.Uint32(data[144:148])
		regs.Ss = binary.LittleEndian.Uint32(data[148:152])
		regs.Ds = binary.LittleEndian.Uint32(data[152:156])
		regs.Es = binary.LittleEndian.Uint32(data[156:160])
		regs.Fs = binary.LittleEndian.Uint32(data[160:164])
		regs.Gs = binary.LittleEndian.Uint32(data[164:168])
	}

	return regs, nil
}

// sliceReg64 reads a register's bytes out of the `g` blob using the discovered
// layout, zero-padding to 8 bytes for sub-uint64 sizes (segment regs are 4).
// Returns 0 if the register isn't in the layout or extends past the blob.
func sliceReg64(blob []byte, layout *RegLayout, name string) uint64 {
	info, ok := layout.ByName[name]
	if !ok {
		return 0
	}
	if info.Offset+info.ByteSize > len(blob) {
		return 0
	}
	var buf [8]byte
	n := info.ByteSize
	if n > 8 {
		n = 8
	}
	copy(buf[:], blob[info.Offset:info.Offset+n])
	return binary.LittleEndian.Uint64(buf[:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (q *QemuDbg) SetReg(regNum int, value uint64) error {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	hexValue := hex.EncodeToString(buf)

	cmd := fmt.Sprintf("P%x=%s", regNum, hexValue)
	resp, err := q.readResponse(cmd)
	if err != nil {
		return err
	}

	if resp != "OK" {
		return fmt.Errorf("failed to set register: %s", resp)
	}

	return nil
}

func (q *QemuDbg) SetBreakpoint(addr uintptr) error {
	cmd := fmt.Sprintf("Z0,%x,1", addr)
	resp, err := q.readResponse(cmd)
	if err != nil {
		return err
	}

	if resp != "OK" && resp != "" {
		return fmt.Errorf("failed to set breakpoint: %s", resp)
	}

	return nil
}

func (q *QemuDbg) RemoveBreakpoint(addr uintptr) error {
	cmd := fmt.Sprintf("z0,%x,1", addr)
	resp, err := q.readResponse(cmd)
	if err != nil {
		return err
	}

	if resp != "OK" && resp != "" {
		return fmt.Errorf("failed to remove breakpoint: %s", resp)
	}

	return nil
}

func (q *QemuDbg) GetRip() (uint64, error) {
	regs, err := q.GetRegs()
	if err != nil {
		return 0, err
	}
	return regs.Rip, nil
}

func (q *QemuDbg) SetRip(rip uint64) error {
	regnum := 16
	if q.regLayout != nil {
		if info, ok := q.regLayout.ByName["rip"]; ok {
			regnum = info.RegNum
		}
	}
	return q.SetReg(regnum, rip)
}

func parseAddr(s string) (uint64, error) {
	return strconv.ParseUint(s, 0, 64)
}

func RunQemuDebugger(host string, port int) error {
	dbg, err := Connect(host, port)
	if err != nil {
		return fmt.Errorf("failed to connect to QEMU: %v", err)
	}
	defer dbg.Close()

	dbg.Interactive()
	return nil
}

func (q *QemuDbg) DisassOne(addr uintptr) (*string, error) {
	code, err := q.GetMemory(16, addr)
	if err != nil {
		return nil, err
	}

	result := fmt.Sprintf("%02x %02x %02x %02x", code[0], code[1], code[2], code[3])
	return &result, nil
}

func (q *QemuDbg) GetProcMaps() []interface{} {
	return []interface{}{}
}

func (q *QemuDbg) IsActive() bool {
	return q.conn != nil && q.isStart
}

func (q *QemuDbg) ResolveAddrToSymbol(addr uint64) (interface{}, uint64, error) {
	return nil, 0, fmt.Errorf("symbol resolution not available for QEMU remote debugging")
}

// GetCR3 returns the value of the CR3 control register.
//
// QEMU >= 8.0 declares cr3 in its GDB target description (i386-64bit.xml), so
// we read it through the standard p<regnum> packet using the regnum we
// discovered at connect time. For older builds where cr3 is absent from
// target.xml, we fall back to parsing `monitor info registers` over qRcmd.
// The previous heuristic that scanned the `g` blob for page-aligned values
// has been retired — it was unreliable across QEMU versions and configurations.
func (q *QemuDbg) GetCR3() (uint64, error) {
	if q.regLayout != nil {
		if _, ok := q.regLayout.ByName["cr3"]; ok {
			return q.GetRegisterByName("cr3")
		}
	}
	return q.cr3FromMonitor()
}
