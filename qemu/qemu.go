package qemu

import (
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
	return dbg, nil
}

func (q *QemuDbg) Close() error {
	if q.conn != nil {
		// Send detach packet to properly disconnect from QEMU
		// This allows QEMU to continue running normally
		q.sendPacket("D")
		// Don't wait for response, just close
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

	// Retry up to 3 times if we get a NACK
	for retry := 0; retry < 3; retry++ {
		_, err := q.conn.Write([]byte(packet))
		if err != nil {
			return err
		}

		// Wait for acknowledgment with timeout
		q.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ackBuf := make([]byte, 1)
		n, err := q.conn.Read(ackBuf)
		q.conn.SetReadDeadline(time.Time{}) // Clear deadline

		if err != nil {
			// On timeout or error, retry
			if retry < 2 {
				continue
			}
			return fmt.Errorf("failed to read ack: %v", err)
		}

		if n > 0 && ackBuf[0] == '+' {
			return nil // Success
		} else if n > 0 && ackBuf[0] == '-' {
			// NACK received, retry
			continue
		}
		// If we got something else, try to handle it as part of response
		// This can happen with packets that don't expect ack
		return nil
	}

	return fmt.Errorf("failed to send packet after 3 retries")
}

func (q *QemuDbg) recvPacket() (string, error) {
	// Set read timeout to prevent infinite blocking
	q.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer q.conn.SetReadDeadline(time.Time{}) // Clear deadline when done

	buf := make([]byte, 8192)
	n, err := q.conn.Read(buf)
	if err != nil {
		return "", err
	}

	response := string(buf[:n])

	// Handle ack/nack at beginning
	response = strings.TrimPrefix(response, "+")
	response = strings.TrimPrefix(response, "-")

	// Parse packet format: $<data>#<checksum>
	if strings.Contains(response, "$") && strings.Contains(response, "#") {
		startIdx := strings.Index(response, "$")
		endIdx := strings.Index(response, "#")
		if startIdx >= 0 && endIdx > startIdx && endIdx+2 < len(response) {
			data := response[startIdx+1 : endIdx]
			checksumStr := response[endIdx+1 : endIdx+3]

			// Validate checksum
			expectedChecksum := byte(0)
			for i := 0; i < len(data); i++ {
				expectedChecksum += data[i]
			}

			// Parse received checksum
			var receivedChecksum byte
			fmt.Sscanf(checksumStr, "%02x", &receivedChecksum)

			if expectedChecksum == receivedChecksum {
				// Send ACK
				_, _ = q.conn.Write([]byte("+"))
				return data, nil
			} else {
				// Send NACK
				_, _ = q.conn.Write([]byte("-"))
				return "", fmt.Errorf("checksum mismatch")
			}
		}
	}

	// If no packet format, just return the response (some responses are just OK, etc.)
	response = strings.TrimSpace(response)
	if response != "" {
		_, _ = q.conn.Write([]byte("+"))
	}

	return response, nil
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

	if resp == "E00" || resp == "" {
		return nil, errors.New("failed to read memory")
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

func (q *QemuDbg) GetRegs() (*Regs, error) {
	resp, err := q.readResponse("g")
	if err != nil {
		return nil, err
	}

	// Clean response
	resp = strings.TrimSpace(resp)

	data, err := hex.DecodeString(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode registers: %v (response: %s)", err, resp[:min(len(resp), 50)])
	}

	if len(data) < 8*17 {
		return nil, fmt.Errorf("insufficient register data: got %d bytes, need at least %d", len(data), 8*17)
	}

	regs := &Regs{}
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
	return q.SetReg(16, rip) // RIP is register 16 in GDB protocol
}

func parseAddr(s string) (uint64, error) {
	return strconv.ParseUint(s, 0, 64)
}

// RunQemuDebugger connects to QEMU and starts an interactive debugging session
func RunQemuDebugger(host string, port int) error {
	dbg, err := Connect(host, port)
	if err != nil {
		return fmt.Errorf("failed to connect to QEMU: %v", err)
	}
	defer dbg.Close()

	dbg.Interactive()
	return nil
}
