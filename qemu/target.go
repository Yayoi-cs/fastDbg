package qemu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RegInfo describes a single register exposed by QEMU's GDB target description.
type RegInfo struct {
	Name     string
	RegNum   int
	Offset   int
	ByteSize int
}

// RegLayout is the register layout discovered from target.xml.
type RegLayout struct {
	ByName map[string]*RegInfo
	Order  []*RegInfo
	Total  int
}

var (
	reInclude = regexp.MustCompile(`<\s*xi:include\s+href\s*=\s*"([^"]+)"`)
	reReg     = regexp.MustCompile(`<\s*reg\s+([^/>]+)/?>`)
	reAttr    = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"([^"]*)"`)
	reComment = regexp.MustCompile(`(?s)<!--.*?-->`)
)

func (q *QemuDbg) readQXferAll(annex string) (string, error) {
	var sb strings.Builder
	offset := 0
	const chunk = 0x400

	for {
		cmd := fmt.Sprintf("qXfer:features:read:%s:%x,%x", annex, offset, chunk)
		resp, err := q.readResponse(cmd)
		if err != nil {
			return "", err
		}
		if len(resp) == 0 {
			return "", fmt.Errorf("empty qXfer response for %s", annex)
		}
		if resp[0] == 'E' {
			return "", fmt.Errorf("qXfer:%s error: %s", annex, resp)
		}
		prefix := resp[0]
		body := decodeGdbEscapes(resp[1:])
		sb.WriteString(body)
		offset += len(body)
		if prefix == 'l' {
			return sb.String(), nil
		}
		if prefix != 'm' {
			return "", fmt.Errorf("unexpected qXfer prefix %q for %s", prefix, annex)
		}
		if len(body) == 0 {
			return sb.String(), nil
		}
	}
}

func decodeGdbEscapes(s string) string {
	if !strings.ContainsRune(s, '}') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '}' && i+1 < len(s) {
			b.WriteByte(s[i+1] ^ 0x20)
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// loadRegLayout fetches target.xml plus any <xi:include>'d files and builds a
// register table keyed by name. Register order in QEMU's `g` packet matches
// the declaration order across all included feature files, with regnums
// either explicit or implicitly running.
func (q *QemuDbg) loadRegLayout() (*RegLayout, error) {
	raw, err := q.readQXferAll("target.xml")
	if err != nil {
		return nil, err
	}

	docs := []string{raw}
	// Resolve includes against the comment-stripped raw, so we don't follow
	// <xi:include> nodes that live inside an XML comment.
	for _, m := range reInclude.FindAllStringSubmatch(reComment.ReplaceAllString(raw, ""), -1) {
		sub, err := q.readQXferAll(m[1])
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %s: %v", m[1], err)
		}
		docs = append(docs, sub)
	}

	layout := &RegLayout{ByName: make(map[string]*RegInfo)}
	nextRegNum := 0
	offset := 0

	for _, doc := range docs {
		// Strip XML comments before scanning for <reg> — QEMU's i386-64bit.xml
		// has commented-out segment-base regs (cs_base/ss_base/ds_base/es_base)
		// that look like real <reg/> tags to a regex.
		doc = reComment.ReplaceAllString(doc, "")
		for _, m := range reReg.FindAllStringSubmatch(doc, -1) {
			attrs := parseAttrs(m[1])
			name := attrs["name"]
			bitsStr, hasBits := attrs["bitsize"]
			if name == "" || !hasBits {
				continue
			}
			bits, err := strconv.Atoi(bitsStr)
			if err != nil || bits <= 0 {
				continue
			}
			byteSize := (bits + 7) / 8

			regnum := nextRegNum
			if rs, ok := attrs["regnum"]; ok {
				if v, err := strconv.Atoi(rs); err == nil {
					regnum = v
				}
			}

			info := &RegInfo{
				Name:     name,
				RegNum:   regnum,
				Offset:   offset,
				ByteSize: byteSize,
			}
			if _, exists := layout.ByName[name]; !exists {
				layout.ByName[name] = info
			}
			layout.Order = append(layout.Order, info)
			offset += byteSize
			nextRegNum = regnum + 1
		}
	}
	layout.Total = offset
	return layout, nil
}

func parseAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range reAttr.FindAllStringSubmatch(s, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// GetRegisterByName reads a single register declared in target.xml.
// Uses the GDB single-register read packet `p<n>`. Register must be ≤8 bytes.
func (q *QemuDbg) GetRegisterByName(name string) (uint64, error) {
	if q.regLayout == nil {
		return 0, fmt.Errorf("register layout not loaded")
	}
	info, ok := q.regLayout.ByName[name]
	if !ok {
		return 0, fmt.Errorf("register %q not exposed by QEMU target description", name)
	}
	if info.ByteSize > 8 {
		return 0, fmt.Errorf("register %q is %d bytes; cannot fit in uint64", name, info.ByteSize)
	}

	cmd := fmt.Sprintf("p%x", info.RegNum)
	resp, err := q.readResponse(cmd)
	if err != nil {
		return 0, err
	}
	resp = strings.TrimSpace(resp)
	if resp == "" || resp[0] == 'E' {
		return 0, fmt.Errorf("p%x failed: %s", info.RegNum, resp)
	}
	data, err := hex.DecodeString(resp)
	if err != nil {
		return 0, fmt.Errorf("decode p%x response: %v", info.RegNum, err)
	}
	if len(data) < info.ByteSize {
		return 0, fmt.Errorf("short response for %q: got %d bytes, want %d", name, len(data), info.ByteSize)
	}

	var buf [8]byte
	copy(buf[:], data[:info.ByteSize])
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// runMonitor sends a QEMU monitor command via qRcmd and returns concatenated stdout.
// QEMU streams the output as one or more `O<hex>` packets followed by `OK`.
func (q *QemuDbg) runMonitor(cmd string) (string, error) {
	hexCmd := hex.EncodeToString([]byte(cmd))
	if err := q.sendPacket("qRcmd," + hexCmd); err != nil {
		return "", err
	}

	var sb strings.Builder
	for {
		resp, err := q.recvPacket()
		if err != nil {
			return "", err
		}
		if resp == "" || resp == "OK" {
			return sb.String(), nil
		}
		if resp[0] == 'E' {
			return sb.String(), fmt.Errorf("qRcmd error: %s", resp)
		}
		if resp[0] == 'O' {
			data, err := hex.DecodeString(resp[1:])
			if err == nil {
				sb.Write(data)
			} else {
				sb.WriteString(resp[1:])
			}
			continue
		}
		sb.WriteString(resp)
		return sb.String(), nil
	}
}

// GetPhysMemory reads `size` bytes of physical memory via QEMU's `xp` monitor
// command. The standard GDB `m` packet runs through the CPU's current MMU, so
// it can't reach raw physical addresses — page-table-walk code must use this.
//
// `xp /<N>bx 0x<addr>` prints output like:
//
//	0000000001ca4ff8: 0x67 0x80 0xc4 0x18 0x10 0x00 0x00 0x00
//
// We extract the bytes with a simple regex.
func (q *QemuDbg) GetPhysMemory(size uint, addr uintptr) ([]byte, error) {
	cmd := fmt.Sprintf("xp /%dbx 0x%x", size, addr)
	out, err := q.runMonitor(cmd)
	if err != nil {
		return nil, fmt.Errorf("xp failed: %v", err)
	}

	re := regexp.MustCompile(`0x([0-9a-fA-F]{1,2})\b`)
	matches := re.FindAllStringSubmatch(out, -1)
	if uint(len(matches)) < size {
		return nil, fmt.Errorf("xp returned %d bytes, expected %d (raw: %q)", len(matches), size, strings.TrimSpace(out))
	}

	data := make([]byte, size)
	for i := uint(0); i < size; i++ {
		v, err := strconv.ParseUint(matches[i][1], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("parse byte %d: %v", i, err)
		}
		data[i] = byte(v)
	}
	return data, nil
}

// cr3FromMonitor parses CR3 out of `monitor info registers` output.
// Used as a fallback when the QEMU build doesn't expose cr3 in target.xml
// (i.e. QEMU < 8.0).
func (q *QemuDbg) cr3FromMonitor() (uint64, error) {
	out, err := q.runMonitor("info registers")
	if err != nil {
		return 0, err
	}
	re := regexp.MustCompile(`(?i)CR3\s*=\s*([0-9a-fA-F]+)`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("CR3 not found in `info registers` output")
	}
	return strconv.ParseUint(m[1], 16, 64)
}
