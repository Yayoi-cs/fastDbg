package findruction

import (
	"bytes"
	"debug/elf"
	"fastDbg/common"
	"fmt"
	"os"
	"sort"
	"sync"
)

// Match is one occurrence of the assembled pattern.
type Match struct {
	// Vaddr is the virtual address of the match. For ELF-mode matches it's
	// the file's virtual address (PIE base added later if relevant); for
	// memory-mode matches it's the absolute runtime address.
	Vaddr uint64
	// FileOffset is the file offset within the ELF; 0 for memory-mode.
	FileOffset uint64
}

// Group bundles matches under one source — either a library file (default
// mode) or an executable memory region (range mode).
type Group struct {
	// Label identifies the source (library path, or "path [start-end]" for
	// runtime regions).
	Label string
	// Path is the underlying file path; empty if not file-backed (e.g. [vdso]).
	Path string
	// LoadBase is the runtime virtual base used to translate Match.Vaddr to
	// an absolute address. 0 when matches are already absolute.
	LoadBase uint64
	Matches  []Match
	Err      error
}

// SearchELF reads the ELF at `path`, walks every PT_LOAD segment with the
// PF_X flag, and returns all occurrences of `pattern` in those segments.
// Vaddr in returned Matches is the file-internal virtual address (i.e.
// p_vaddr + offset within segment), so callers add the PIE base if they
// want a runtime address.
//
// We deliberately read straight from the file rather than from the live
// mapping so search covers every executable byte the linker laid out, even
// pages the kernel hasn't faulted in yet.
func SearchELF(path string, pattern []byte) ([]Match, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var matches []Match
	for _, ph := range f.Progs {
		if ph.Type != elf.PT_LOAD || ph.Flags&elf.PF_X == 0 {
			continue
		}
		start := ph.Off
		end := start + ph.Filesz
		if end > uint64(len(raw)) || start >= end {
			continue
		}
		seg := raw[start:end]
		for _, idx := range allIndices(seg, pattern) {
			matches = append(matches, Match{
				FileOffset: ph.Off + uint64(idx),
				Vaddr:      ph.Vaddr + uint64(idx),
			})
		}
	}
	return matches, nil
}

// SearchAllLibraries searches every path in `libs` in parallel and returns
// a Group per library. Used by the default (no-address) mode. Even though
// each goroutine does file I/O serially, parallelism wins on multi-core
// systems because ELF parsing and Boyer-Moore on multi-megabyte segments
// is CPU-bound.
//
// `loadBases` (parallel slice to libs) is the runtime base of each library
// (0 if not loaded yet) so the caller can show absolute addresses.
func SearchAllLibraries(libs []string, loadBases []uint64, pattern []byte) []Group {
	results := make([]Group, len(libs))
	var wg sync.WaitGroup
	for i := range libs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = Group{Label: libs[idx], Path: libs[idx]}
			if idx < len(loadBases) {
				results[idx].LoadBase = loadBases[idx]
			}
			m, err := SearchELF(libs[idx], pattern)
			if err != nil {
				results[idx].Err = err
				return
			}
			results[idx].Matches = m
		}(i)
	}
	wg.Wait()
	return results
}

// ExecRegion describes a runtime executable mapping.
type ExecRegion struct {
	Start uint64
	End   uint64
	Path  string
}

// SearchMemoryRange reads the live executable mappings in `regions` (clipped
// to [start, end] when those are non-zero) via `r` and returns a Group per
// region that contains at least one match. Used when the user supplies an
// address range. Sequential by design — `r` (a ptrace/QEMU backend) is
// already serialised at its worker so goroutines wouldn't help.
func SearchMemoryRange(r common.Reader, regions []ExecRegion, start, end uint64, pattern []byte) []Group {
	var groups []Group
	for _, reg := range regions {
		rs, re := reg.Start, reg.End
		if start != 0 {
			if re <= start {
				continue
			}
			if rs < start {
				rs = start
			}
		}
		if end != 0 {
			if rs >= end {
				continue
			}
			if re > end {
				re = end
			}
		}
		if re-rs < uint64(len(pattern)) {
			continue
		}
		buf, err := r.GetMemory(uint(re-rs), uintptr(rs))
		if err != nil {
			groups = append(groups, Group{
				Label: fmt.Sprintf("%s [0x%x-0x%x]", reg.Path, rs, re),
				Path:  reg.Path,
				Err:   err,
			})
			continue
		}
		var matches []Match
		for _, idx := range allIndices(buf, pattern) {
			matches = append(matches, Match{Vaddr: rs + uint64(idx)})
		}
		if len(matches) == 0 {
			continue
		}
		groups = append(groups, Group{
			Label:   fmt.Sprintf("%s [0x%x-0x%x]", reg.Path, rs, re),
			Path:    reg.Path,
			Matches: matches,
		})
	}
	// Stable order by region start address for deterministic output.
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Label < groups[j].Label
	})
	return groups
}

// allIndices returns every starting offset of `needle` in `hay`. We use
// bytes.Index in a loop — runtime's strstr is fast enough that a manual
// Boyer-Moore (which the Rust tool uses) wouldn't measurably help for the
// pattern sizes typical here (a handful of bytes).
func allIndices(hay, needle []byte) []int {
	if len(needle) == 0 || len(hay) < len(needle) {
		return nil
	}
	var out []int
	off := 0
	for off+len(needle) <= len(hay) {
		i := bytes.Index(hay[off:], needle)
		if i < 0 {
			break
		}
		out = append(out, off+i)
		off += i + 1
	}
	return out
}
