package common

import (
	"encoding/binary"
	"strings"
)

// PadCell right-pads s with spaces so its visible (ANSI-stripped) width is
// at least n. Used to align colored cells in side-by-side displays.
func PadCell(s string, n int) string {
	v := VisibleLen(s)
	if v >= n {
		return s + " "
	}
	return s + strings.Repeat(" ", n-v)
}

// VisibleLen returns the rune length of s, ignoring ANSI CSI escape
// sequences (`\x1b[...m`).
func VisibleLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

// ValueToBytes converts a uint64 to little-endian bytes, trimming trailing
// zero bytes down to a minimum of 1 byte. So 0x4141 becomes [0x41, 0x41]
// instead of [0x41, 0x41, 0, 0, 0, 0, 0, 0]. Used by `cyclic -d` and the
// search commands to convert a hex literal into the bytes the user actually
// expects to find in memory.
func ValueToBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	n := 8
	for n > 1 && buf[n-1] == 0 {
		n--
	}
	return buf[:n]
}

// ReadField reads `size` bytes (1, 2, 4, or 8) at `offset` in `buf` as a
// little-endian unsigned integer, zero-extended to uint64. Returns 0 if
// the read would overrun the buffer.
func ReadField(buf []byte, offset, size int) uint64 {
	if offset < 0 || size <= 0 || offset+size > len(buf) {
		return 0
	}
	switch size {
	case 1:
		return uint64(buf[offset])
	case 2:
		return uint64(binary.LittleEndian.Uint16(buf[offset : offset+2]))
	case 4:
		return uint64(binary.LittleEndian.Uint32(buf[offset : offset+4]))
	case 8:
		return binary.LittleEndian.Uint64(buf[offset : offset+8])
	}
	return 0
}
