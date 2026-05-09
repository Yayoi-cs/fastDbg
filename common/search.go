package common

import "bytes"

// SearchInBuffer finds every occurrence of `pattern` in `buf` and returns
// absolute addresses (`baseAddr + offset_in_buf`). Used by callers that
// already have a contiguous block of memory loaded — typically userland,
// where each readable mapping is read in one shot.
func SearchInBuffer(buf []byte, baseAddr uint64, pattern []byte) []uint64 {
	var hits []uint64
	if len(pattern) == 0 || len(buf) < len(pattern) {
		return hits
	}
	offset := 0
	for offset+len(pattern) <= len(buf) {
		idx := bytes.Index(buf[offset:], pattern)
		if idx < 0 {
			break
		}
		hits = append(hits, baseAddr+uint64(offset+idx))
		offset += idx + 1
	}
	return hits
}

// SearchRange walks [start, end) one page at a time through `r`, building
// up contiguous mapped spans, and runs SearchInBuffer on each. Pages whose
// GetMemory returns an error (typically EFAULT for unmapped) flush the
// current span and resume on the next page. This is the strategy used in
// kernel mode where we don't have a /proc/maps and can't know in advance
// what's mapped.
//
// A 16 MB cap on the in-memory span keeps memory usage bounded for very
// large mapped regions; when reached, the bulk is searched and the last
// `len(pattern)-1` bytes are kept so cross-flush matches aren't missed.
func SearchRange(r Reader, start, end uint64, pattern []byte) []uint64 {
	var hits []uint64
	if len(pattern) == 0 || start >= end {
		return hits
	}
	const pageSize uint64 = 0x1000
	const maxSpan = 0x1000000 // 16 MB
	overlap := uint64(len(pattern) - 1)

	pos := start &^ (pageSize - 1)
	if pos < start {
		pos = start
	}

	var span []byte
	spanStart := uint64(0)

	flush := func() {
		if uint64(len(span)) < uint64(len(pattern)) {
			span = nil
			return
		}
		hits = append(hits, SearchInBuffer(span, spanStart, pattern)...)
		span = nil
	}

	for pos < end {
		readSize := pageSize
		if pos+readSize > end {
			readSize = end - pos
		}
		buf, err := r.GetMemory(uint(readSize), uintptr(pos))
		if err != nil {
			flush()
			next := pos + pageSize
			if next < pos {
				break
			}
			pos = next
			continue
		}
		if len(span) == 0 {
			spanStart = pos
		}
		span = append(span, buf...)
		if uint64(len(span)) >= maxSpan {
			searchEnd := len(span) - int(overlap)
			if searchEnd < 0 {
				searchEnd = 0
			}
			head := span[:searchEnd+int(overlap)]
			for _, h := range SearchInBuffer(head, spanStart, pattern) {
				if h-spanStart < uint64(searchEnd) {
					hits = append(hits, h)
				}
			}
			tail := append([]byte(nil), span[searchEnd:]...)
			spanStart = spanStart + uint64(searchEnd)
			span = tail
		}
		next := pos + pageSize
		if next < pos {
			break
		}
		pos = next
	}
	flush()
	return hits
}
