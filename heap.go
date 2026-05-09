package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// glibc 2.35-2.41 / x86_64 constants. The malloc_state layout has been stable
// across these versions; tcache and chunk metadata changed only in details
// captured by the capability flags below.
const (
	heapMallocAlignment = 16
	heapSizeSz          = 8

	heapNFastbins  = 10
	heapNBins      = 128
	heapNSmallbins = 64
	heapNLargebins = 63
	heapBinmapSize = 4
	heapTcacheBins = 64
	heapMinLarge   = 0x400

	chunkPrevInuse     = 0x1
	chunkIsMmapped     = 0x2
	chunkNonMainArena  = 0x4
	chunkSizeBitsMask  = 0x7
	chunkHeaderSize    = 0x10
	chunkMinSize       = 0x20
	chunkSizeAlignMask = ^uint64(chunkSizeBitsMask)

	msOffMutex            = 0
	msOffFlags            = 4
	msOffHaveFastchunks   = 8
	msOffFastbinsY        = 16
	msOffTop              = 96
	msOffLastRemainder    = 104
	msOffBins             = 112
	msOffBinmap           = 2144
	msOffNext             = 2160
	msOffNextFree         = 2168
	msOffAttachedThreads  = 2176
	msOffSystemMem        = 2184
	msOffMaxSystemMem     = 2192
	mallocStateSize       = 2200

	tcOffCounts  = 0
	tcOffEntries = heapTcacheBins * 2
	tcacheStructSize = tcOffEntries + heapTcacheBins*8
)

type libcVersion struct {
	major, minor int
}

func (v libcVersion) String() string { return fmt.Sprintf("%d.%d", v.major, v.minor) }
func (v libcVersion) atLeast(maj, min int) bool {
	return v.major > maj || (v.major == maj && v.minor >= min)
}

type libcInfo struct {
	path             string
	base             uint64
	dataStart        uint64
	dataEnd          uint64
	version          libcVersion
	hasTcache        bool
	hasSafeLinking   bool
	hasTcacheKey     bool
	tcacheCountBytes int

	mainArena uint64
}

type mallocState struct {
	mutex          uint32
	flags          uint32
	haveFastchunks uint32
	fastbinsY      [heapNFastbins]uint64
	top            uint64
	lastRemainder  uint64
	bins           [heapNBins*2 - 2]uint64
	binmap         [heapBinmapSize]uint32
	next           uint64
	nextFree       uint64
	attachedThreads uint64
	systemMem      uint64
	maxSystemMem   uint64
}

type mallocChunk struct {
	addr     uint64
	prevSize uint64
	size     uint64
	fd       uint64
	bk       uint64
	fdNS     uint64
	bkNS     uint64
}

func (c *mallocChunk) chunkSize() uint64 { return c.size & chunkSizeAlignMask }
func (c *mallocChunk) prevInuse() bool   { return c.size&chunkPrevInuse != 0 }
func (c *mallocChunk) isMmapped() bool   { return c.size&chunkIsMmapped != 0 }
func (c *mallocChunk) nonMainArena() bool { return c.size&chunkNonMainArena != 0 }

var cachedLibc *libcInfo

// detectLibc finds the loaded libc, reads its version, and locates its writable
// data segment. The result is cached for the rest of the session — invalidate
// by calling invalidateLibcCache() if the debuggee restarts.
func (dbger *TypeDbg) detectLibc() (*libcInfo, error) {
	if cachedLibc != nil && cachedLibc.base != 0 {
		return cachedLibc, nil
	}

	var libcPath string
	var libcBase uint64
	for i := range libRoots {
		name := libRoots[i].name
		if isLibcPath(name) && libRoots[i].base != 0 {
			libcPath = name
			libcBase = libRoots[i].base
			break
		}
	}
	if libcPath == "" {
		return nil, errors.New("libc not found in loaded libraries (process may not be started)")
	}

	var dataStart, dataEnd uint64
	for _, p := range procMapsDetail {
		if p.path == libcPath && p.r && p.w && !p.x {
			if dataStart == 0 || p.start < dataStart {
				dataStart = p.start
			}
			if p.end > dataEnd {
				dataEnd = p.end
			}
		}
	}
	if dataStart == 0 {
		return nil, fmt.Errorf("libc data segment not found in /proc maps for %s", libcPath)
	}

	ver, err := readLibcVersion(libcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read libc version: %v", err)
	}

	li := &libcInfo{
		path:             libcPath,
		base:             libcBase,
		dataStart:        dataStart,
		dataEnd:          dataEnd,
		version:          ver,
		hasTcache:        ver.atLeast(2, 26),
		hasSafeLinking:   ver.atLeast(2, 32),
		hasTcacheKey:     ver.atLeast(2, 34),
		tcacheCountBytes: 2,
	}
	if !ver.atLeast(2, 30) {
		li.tcacheCountBytes = 1
	}

	cachedLibc = li
	return li, nil
}

func invalidateLibcCache() { cachedLibc = nil }

func isLibcPath(p string) bool {
	base := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		base = p[i+1:]
	}
	return strings.HasPrefix(base, "libc.so") || strings.HasPrefix(base, "libc-")
}

var reLibcVersion = regexp.MustCompile(`GNU C Library[^,]*release version (\d+)\.(\d+)`)

func readLibcVersion(path string) (libcVersion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return libcVersion{}, err
	}
	m := reLibcVersion.FindSubmatch(data)
	if m == nil {
		return libcVersion{}, errors.New("version string not found in libc binary")
	}
	maj, _ := strconv.Atoi(string(m[1]))
	min, _ := strconv.Atoi(string(m[2]))
	return libcVersion{major: maj, minor: min}, nil
}

// findMainArena locates main_arena in the libc data segment.
//
// Strategy depends on whether the program has malloc'd yet:
//
//  - With [heap]: anchor on `system_mem == heap_size`. main_arena's
//    system_mem field exactly tracks total brk extension, which equals
//    heap_end - heap_start. Scan libc data for that 8-byte value, treat
//    each hit as a candidate's system_mem field, subtract msOffSystemMem
//    to get the candidate base, then validate by checking that `top` is
//    in [heap]. This is far more selective than the bins[0] self-loop
//    pattern (which repeats every 16 bytes through the bins array and
//    fails to uniquely identify the arena base).
//
//  - Without [heap]: pre-malloc state. Use bins[0] self-loop AND
//    top == initial fake top (candidate+96) — both must hold and they
//    don't have the +16 ambiguity in this state because `top` of the
//    +16 ghost would read bins[0] of the real arena, which equals the
//    real arena's +96, not the ghost's +96.
func (dbger *TypeDbg) findMainArena(li *libcInfo) (uint64, error) {
	if li.mainArena != 0 {
		return li.mainArena, nil
	}

	dataLen := li.dataEnd - li.dataStart
	if dataLen < mallocStateSize {
		return 0, fmt.Errorf("libc data segment too small (%d bytes)", dataLen)
	}

	buf, err := dbger.GetMemory(uint(dataLen), uintptr(li.dataStart))
	if err != nil {
		return 0, fmt.Errorf("failed to read libc data segment: %v", err)
	}

	heapStart, heapEnd, hasHeap := dbger.findMainHeap()

	if hasHeap {
		heapSize := heapEnd - heapStart
		for off := uint64(0); off+8 <= uint64(len(buf)); off += 8 {
			val := binary.LittleEndian.Uint64(buf[off:])
			if val != heapSize {
				continue
			}
			if off < msOffSystemMem {
				continue
			}
			candOff := off - msOffSystemMem
			if candOff+mallocStateSize > uint64(len(buf)) {
				continue
			}
			candidate := li.dataStart + candOff

			top := binary.LittleEndian.Uint64(buf[candOff+msOffTop:])
			if top < heapStart || top >= heapEnd {
				continue
			}

			next := binary.LittleEndian.Uint64(buf[candOff+msOffNext:])
			if next == 0 {
				continue
			}
			if next != candidate {
				if !dbger.isWritableAddr(next) {
					continue
				}
				if next >= li.dataStart && next < li.dataEnd {
					continue
				}
			}

			attached := binary.LittleEndian.Uint64(buf[candOff+msOffAttachedThreads:])
			if attached == 0 || attached > 4096 {
				continue
			}

			li.mainArena = candidate
			return candidate, nil
		}
		return 0, fmt.Errorf("main_arena not found: no system_mem=0x%x match in libc.data", heapSize)
	}

	// No [heap] — pre-malloc. Anchor on bins[0]==bins[1]==arena+96 plus
	// initial fake top.
	for off := uint64(0); off+mallocStateSize <= uint64(len(buf)); off += 8 {
		candidate := li.dataStart + off
		bins0 := binary.LittleEndian.Uint64(buf[off+msOffBins:])
		bins1 := binary.LittleEndian.Uint64(buf[off+msOffBins+8:])
		expectedSelf := candidate + msOffBins - chunkHeaderSize
		if bins0 != expectedSelf || bins1 != expectedSelf {
			continue
		}
		top := binary.LittleEndian.Uint64(buf[off+msOffTop:])
		if top != expectedSelf {
			continue
		}
		li.mainArena = candidate
		return candidate, nil
	}
	return 0, errors.New("main_arena not found in libc data segment")
}

func (dbger *TypeDbg) isWritableAddr(addr uint64) bool {
	if addr == 0 {
		return false
	}
	for _, p := range procMapsDetail {
		if addr >= p.start && addr < p.end && p.w {
			return true
		}
	}
	return false
}

// readMallocState reads SIZEOF_MALLOC_STATE bytes from the target process
// and decodes them into the in-memory struct.
func (dbger *TypeDbg) readMallocState(addr uint64) (*mallocState, error) {
	buf, err := dbger.GetMemory(mallocStateSize, uintptr(addr))
	if err != nil {
		return nil, err
	}
	if len(buf) < mallocStateSize {
		return nil, fmt.Errorf("short read for malloc_state at 0x%x", addr)
	}

	ms := &mallocState{
		mutex:          binary.LittleEndian.Uint32(buf[msOffMutex:]),
		flags:          binary.LittleEndian.Uint32(buf[msOffFlags:]),
		haveFastchunks: binary.LittleEndian.Uint32(buf[msOffHaveFastchunks:]),
		top:            binary.LittleEndian.Uint64(buf[msOffTop:]),
		lastRemainder:  binary.LittleEndian.Uint64(buf[msOffLastRemainder:]),
		next:           binary.LittleEndian.Uint64(buf[msOffNext:]),
		nextFree:       binary.LittleEndian.Uint64(buf[msOffNextFree:]),
		attachedThreads: binary.LittleEndian.Uint64(buf[msOffAttachedThreads:]),
		systemMem:      binary.LittleEndian.Uint64(buf[msOffSystemMem:]),
		maxSystemMem:   binary.LittleEndian.Uint64(buf[msOffMaxSystemMem:]),
	}
	for i := 0; i < heapNFastbins; i++ {
		ms.fastbinsY[i] = binary.LittleEndian.Uint64(buf[msOffFastbinsY+i*8:])
	}
	for i := 0; i < heapNBins*2-2; i++ {
		ms.bins[i] = binary.LittleEndian.Uint64(buf[msOffBins+i*8:])
	}
	for i := 0; i < heapBinmapSize; i++ {
		ms.binmap[i] = binary.LittleEndian.Uint32(buf[msOffBinmap+i*4:])
	}
	return ms, nil
}

func (dbger *TypeDbg) readChunk(addr uint64) (*mallocChunk, error) {
	buf, err := dbger.GetMemory(48, uintptr(addr))
	if err != nil {
		return nil, err
	}
	c := &mallocChunk{addr: addr}
	if len(buf) >= 8 {
		c.prevSize = binary.LittleEndian.Uint64(buf[0:8])
	}
	if len(buf) >= 16 {
		c.size = binary.LittleEndian.Uint64(buf[8:16])
	}
	if len(buf) >= 24 {
		c.fd = binary.LittleEndian.Uint64(buf[16:24])
	}
	if len(buf) >= 32 {
		c.bk = binary.LittleEndian.Uint64(buf[24:32])
	}
	if len(buf) >= 40 {
		c.fdNS = binary.LittleEndian.Uint64(buf[32:40])
	}
	if len(buf) >= 48 {
		c.bkNS = binary.LittleEndian.Uint64(buf[40:48])
	}
	return c, nil
}

// revealPtr reverses glibc's PROTECT_PTR encoding (≥2.32). The decoded value
// is stored at `pos` and was obfuscated as `value ^ (pos >> 12)`.
func revealPtr(pos, encoded uint64) uint64 {
	return encoded ^ (pos >> 12)
}

// ---- bin walkers --------------------------------------------------------

func fastbinChunkSize(idx int) uint64 { return uint64(chunkMinSize + idx*heapMallocAlignment) }
func tcacheChunkSize(idx int) uint64  { return uint64(chunkMinSize + idx*heapMallocAlignment) }
func smallbinChunkSize(idx int) uint64 {
	// smallbin index 1 corresponds to size 0x20 (i.e. bin 2 in arena.bins);
	// we keep callers using the arena's 1-indexed bin numbering.
	return uint64(idx * heapMallocAlignment)
}

// walkFastbin walks one fastbin chain. Safe-linking applies since glibc 2.32
// — each `next` is encoded as `addr ^ (chunk_addr >> 12)`.
func (dbger *TypeDbg) walkFastbin(li *libcInfo, head uint64) ([]uint64, error) {
	var chain []uint64
	curr := head
	visited := map[uint64]bool{}
	for curr != 0 && !visited[curr] && len(chain) < 256 {
		visited[curr] = true
		chain = append(chain, curr)

		nextRaw, err := dbger.readQword(curr + chunkHeaderSize)
		if err != nil {
			break
		}
		var next uint64
		if li.hasSafeLinking {
			next = revealPtr(curr, nextRaw)
		} else {
			next = nextRaw
		}
		if next == 0 {
			break
		}
		curr = next
	}
	return chain, nil
}

// walkTcacheBin walks one tcache bin chain starting at the entry pointer
// stored in tcache_perthread_struct.entries[idx].
func (dbger *TypeDbg) walkTcacheBin(li *libcInfo, head uint64, claimed int) ([]uint64, error) {
	var chain []uint64
	if head == 0 {
		return chain, nil
	}
	curr := head
	visited := map[uint64]bool{}
	for curr != 0 && !visited[curr] && len(chain) < claimed && len(chain) < 1024 {
		visited[curr] = true
		chain = append(chain, curr)

		nextRaw, err := dbger.readQword(curr)
		if err != nil {
			break
		}
		var next uint64
		if li.hasSafeLinking {
			next = revealPtr(curr, nextRaw)
		} else {
			next = nextRaw
		}
		if next == 0 {
			break
		}
		curr = next
	}
	return chain, nil
}

// walkBin walks a doubly-linked bin (unsorted/small/large). Returns the chain
// of chunk addresses (not the bin head). Detects circular and corrupted lists
// by capping iterations and tracking visited addresses.
func (dbger *TypeDbg) walkBin(arenaAddr uint64, ms *mallocState, binIdx int) ([]uint64, error) {
	if binIdx < 1 || binIdx >= heapNBins {
		return nil, fmt.Errorf("bin index %d out of range", binIdx)
	}
	binsArrayIdx := (binIdx - 1) * 2
	binHead := arenaAddr + msOffBins + uint64(binsArrayIdx)*8 - chunkHeaderSize
	fdHead := ms.bins[binsArrayIdx]
	if fdHead == binHead {
		return nil, nil
	}

	var chain []uint64
	visited := map[uint64]bool{}
	curr := fdHead
	for curr != binHead && !visited[curr] && len(chain) < 4096 {
		visited[curr] = true
		chain = append(chain, curr)

		fd, err := dbger.readQword(curr + chunkHeaderSize)
		if err != nil {
			break
		}
		curr = fd
	}
	return chain, nil
}

func (dbger *TypeDbg) readQword(addr uint64) (uint64, error) {
	buf, err := dbger.GetMemory(8, uintptr(addr))
	if err != nil {
		return 0, err
	}
	if len(buf) < 8 {
		return 0, fmt.Errorf("short read at 0x%x", addr)
	}
	return binary.LittleEndian.Uint64(buf), nil
}

// findTcacheStruct locates the tcache_perthread_struct in the heap. Glibc
// initialises tcache lazily — the first malloc carves it out of the top chunk
// and stores it as the *first* in-use chunk at heap_base + 0x10. We don't
// hardcode that offset; instead we walk chunks from heap_base and pick the
// first that's the right size and has plausible counts. Returns 0 if not
// found (tcache may not have been allocated yet).
func (dbger *TypeDbg) findTcacheStruct(heapStart, heapEnd uint64, li *libcInfo) (uint64, error) {
	curr := heapStart
	for steps := 0; steps < 64 && curr < heapEnd; steps++ {
		c, err := dbger.readChunk(curr)
		if err != nil {
			return 0, err
		}
		sz := c.chunkSize()
		if sz == 0 || sz > heapEnd-curr {
			return 0, nil
		}
		userAddr := curr + chunkHeaderSize
		userSize := sz - chunkHeaderSize
		if userSize >= tcacheStructSize {
			ok, err := dbger.tcacheStructLooksValid(userAddr, li)
			if err == nil && ok {
				return userAddr, nil
			}
		}
		curr += sz
	}
	return 0, nil
}

func (dbger *TypeDbg) tcacheStructLooksValid(addr uint64, li *libcInfo) (bool, error) {
	buf, err := dbger.GetMemory(uint(tcacheStructSize), uintptr(addr))
	if err != nil || len(buf) < tcacheStructSize {
		return false, err
	}
	for i := 0; i < heapTcacheBins; i++ {
		var cnt int
		if li.tcacheCountBytes == 1 {
			cnt = int(buf[i])
		} else {
			cnt = int(binary.LittleEndian.Uint16(buf[i*2:]))
		}
		entry := binary.LittleEndian.Uint64(buf[tcOffEntries+i*8:])
		if cnt == 0 && entry != 0 {
			return false, nil
		}
		if cnt > 1024 {
			return false, nil
		}
	}
	return true, nil
}

// heapView wraps a cached chunk of heap memory so bin walkers can fetch fd/bk
// pointers without round-tripping through ptrace for every read. When a
// pointer falls outside the cached range, the walker falls back to GetMemory.
type heapView struct {
	dbger      *TypeDbg
	heapStart  uint64
	heapEnd    uint64
	heap       []byte
}

func (h *heapView) qword(addr uint64) (uint64, error) {
	if addr >= h.heapStart && addr+8 <= h.heapEnd {
		return binary.LittleEndian.Uint64(h.heap[addr-h.heapStart:]), nil
	}
	return h.dbger.readQword(addr)
}

// walkFastbinView is the cached-memory variant of walkFastbin.
func (h *heapView) walkFastbin(li *libcInfo, head uint64) []uint64 {
	var chain []uint64
	visited := map[uint64]bool{}
	curr := head
	for curr != 0 && !visited[curr] && len(chain) < 4096 {
		visited[curr] = true
		chain = append(chain, curr)
		raw, err := h.qword(curr + chunkHeaderSize)
		if err != nil {
			break
		}
		if li.hasSafeLinking {
			curr = revealPtr(curr, raw)
		} else {
			curr = raw
		}
	}
	return chain
}

func (h *heapView) walkTcacheBin(li *libcInfo, head uint64, claimed int) []uint64 {
	var chain []uint64
	if head == 0 {
		return chain
	}
	cap := claimed
	if cap <= 0 || cap > 1024 {
		cap = 1024
	}
	visited := map[uint64]bool{}
	curr := head
	for curr != 0 && !visited[curr] && len(chain) < cap {
		visited[curr] = true
		chain = append(chain, curr)
		raw, err := h.qword(curr)
		if err != nil {
			break
		}
		if li.hasSafeLinking {
			curr = revealPtr(curr, raw)
		} else {
			curr = raw
		}
	}
	return chain
}

func (h *heapView) walkBin(arenaAddr uint64, ms *mallocState, binIdx int) []uint64 {
	if binIdx < 1 || binIdx >= heapNBins {
		return nil
	}
	binsArrayIdx := (binIdx - 1) * 2
	binHead := arenaAddr + msOffBins + uint64(binsArrayIdx)*8 - chunkHeaderSize
	curr := ms.bins[binsArrayIdx]
	if curr == binHead {
		return nil
	}
	var chain []uint64
	visited := map[uint64]bool{}
	for curr != binHead && !visited[curr] && len(chain) < 4096 {
		visited[curr] = true
		chain = append(chain, curr)
		fd, err := h.qword(curr + chunkHeaderSize)
		if err != nil {
			break
		}
		curr = fd
	}
	return chain
}

// snapshotHeap captures every bin (tcache/fastbin/unsorted/small/large) of
// the main arena into a single struct. Bin walks fetch fd/bk pointers from
// cached heap memory when possible.
type heapSnapshot struct {
	libc        *libcInfo
	arena       uint64
	state       *mallocState
	heapStart   uint64
	heapEnd     uint64
	heap        []byte
	tcacheAddr  uint64
	tcacheCount [heapTcacheBins]int
	tcache      [heapTcacheBins][]uint64
	fastbin     [heapNFastbins][]uint64
	binChain    [heapNBins][]uint64
}

// snapshotMainArena is a thin wrapper: detect libc, locate main_arena, snapshot.
func (dbger *TypeDbg) snapshotMainArena() (*heapSnapshot, error) {
	li, err := dbger.detectLibc()
	if err != nil {
		return nil, err
	}
	arena, err := dbger.findMainArena(li)
	if err != nil {
		return nil, err
	}
	return dbger.snapshotArena(li, arena, arena)
}

// snapshotArena captures every bin of `arena`. `mainArena` is provided so we
// can tell whether `arena` is the main one (its heap is in [heap]) or a
// thread arena (its heap is an mmap'd region; we skip caching it).
func (dbger *TypeDbg) snapshotArena(li *libcInfo, arena, mainArena uint64) (*heapSnapshot, error) {
	ms, err := dbger.readMallocState(arena)
	if err != nil {
		return nil, err
	}

	snap := &heapSnapshot{
		libc:  li,
		arena: arena,
		state: ms,
	}

	if arena == mainArena {
		heapStart, heapEnd, hasHeap := dbger.findMainHeap()
		if hasHeap {
			snap.heapStart = heapStart
			snap.heapEnd = heapEnd
			snap.heap, _ = dbger.GetMemory(uint(heapEnd-heapStart), uintptr(heapStart))
		}
	} else {
		heapStart, heapEnd, hasHeap := dbger.findArenaHeap(arena, mainArena)
		if hasHeap {
			snap.heapStart = heapStart
			snap.heapEnd = heapEnd
			// Don't cache the thread heap eagerly — it can be up to 64MB and
			// is mostly unmapped. Bin walks fall back to GetMemory for fd/bk.
		}
	}

	view := &heapView{dbger: dbger, heapStart: snap.heapStart, heapEnd: snap.heapEnd, heap: snap.heap}

	if li.hasTcache && snap.heapStart != 0 {
		// Tcache search starts at heap_start for main arena; for thread arenas
		// it starts after heap_info + (padded) malloc_state where chunks begin.
		searchStart := snap.heapStart
		if arena != mainArena {
			searchStart = snap.heapStart + sizeofHeapInfo + arenaPaddedSize
		}
		if searchStart < snap.heapEnd {
			if tcAddr, _ := dbger.findTcacheStruct(searchStart, snap.heapEnd, li); tcAddr != 0 {
				snap.tcacheAddr = tcAddr
				if buf, err := dbger.GetMemory(uint(tcacheStructSize), uintptr(tcAddr)); err == nil && len(buf) >= tcacheStructSize {
					for i := 0; i < heapTcacheBins; i++ {
						var cnt int
						if li.tcacheCountBytes == 1 {
							cnt = int(buf[i])
						} else {
							cnt = int(binary.LittleEndian.Uint16(buf[i*2:]))
						}
						entry := binary.LittleEndian.Uint64(buf[tcOffEntries+i*8:])
						snap.tcacheCount[i] = cnt
						snap.tcache[i] = view.walkTcacheBin(li, entry, cnt)
					}
				}
			}
		}
	}

	for i := 0; i < heapNFastbins; i++ {
		head := ms.fastbinsY[i]
		if head == 0 {
			continue
		}
		snap.fastbin[i] = view.walkFastbin(li, head)
	}

	for i := 1; i < heapNBins; i++ {
		snap.binChain[i] = view.walkBin(arena, ms, i)
	}

	return snap, nil
}

// findArenaHeap returns the heap range that backs `arena`. For the main
// arena that's the brk [heap]; for thread arenas it's the mmap'd region of
// up to HEAP_MAX_SIZE that starts with a heap_info struct. Returns (0, 0,
// false) if it can't be located.
const heapMaxSize = 0x4000000 // 64MB
const sizeofHeapInfo = 32
const arenaPaddedSize = 2208 // mallocStateSize aligned up to MALLOC_ALIGNMENT

func (dbger *TypeDbg) findArenaHeap(arena, mainArena uint64) (uint64, uint64, bool) {
	if arena == mainArena {
		return dbger.findMainHeap()
	}
	ms, err := dbger.readMallocState(arena)
	if err != nil {
		return 0, 0, false
	}
	heapInfoAddr := ms.top &^ uint64(heapMaxSize-1)
	buf, err := dbger.GetMemory(uint(sizeofHeapInfo), uintptr(heapInfoAddr))
	if err != nil || len(buf) < sizeofHeapInfo {
		return 0, 0, false
	}
	arPtr := binary.LittleEndian.Uint64(buf[0:8])
	if arPtr != arena {
		return 0, 0, false
	}
	size := binary.LittleEndian.Uint64(buf[16:24])
	if size == 0 || size > heapMaxSize {
		return 0, 0, false
	}
	return heapInfoAddr, heapInfoAddr + size, true
}

// findMmappedChunks scans /proc maps for anonymous rw- regions whose first
// 16 bytes match a valid mmap-chunk header (prev_size == 0, size has
// IS_MMAPPED set and !PREV_INUSE !NON_MAIN_ARENA, and the chunk size ≤
// region size). This catches malloc'd chunks larger than mp_.mmap_threshold,
// which bypass arenas entirely. Returns chunk addresses (= region starts).
func (dbger *TypeDbg) findMmappedChunks(arenas []uint64) []uint64 {
	arenaSet := map[uint64]bool{}
	for _, a := range arenas {
		// Thread arenas live inside an mmap region too; ignore that whole region.
		// Round down to HEAP_MAX_SIZE (64MB) boundary.
		arenaSet[a&^uint64(0x4000000-1)] = true
	}

	var found []uint64
	for _, p := range procMapsDetail {
		if p.path != "" {
			continue
		}
		if !p.r || !p.w || p.x {
			continue
		}
		if arenaSet[p.start&^uint64(0x4000000-1)] {
			continue
		}

		buf, err := dbger.GetMemory(16, uintptr(p.start))
		if err != nil || len(buf) < 16 {
			continue
		}
		prevSize := binary.LittleEndian.Uint64(buf[0:8])
		size := binary.LittleEndian.Uint64(buf[8:16])
		if prevSize != 0 {
			continue
		}
		if size&chunkIsMmapped == 0 {
			continue
		}
		if size&(chunkPrevInuse|chunkNonMainArena) != 0 {
			continue
		}
		actual := size & chunkSizeAlignMask
		if actual < chunkMinSize || actual > p.end-p.start {
			continue
		}
		found = append(found, p.start)
	}
	return found
}

// listArenas walks main_arena.next chain. Returns [main, thread1, thread2, ...].
func (dbger *TypeDbg) listArenas() ([]uint64, *libcInfo, error) {
	li, err := dbger.detectLibc()
	if err != nil {
		return nil, nil, err
	}
	main, err := dbger.findMainArena(li)
	if err != nil {
		return nil, nil, err
	}

	arenas := []uint64{main}
	visited := map[uint64]bool{main: true}
	curr := main
	for len(arenas) < 64 {
		ms, err := dbger.readMallocState(curr)
		if err != nil {
			break
		}
		nxt := ms.next
		if nxt == 0 || nxt == main || visited[nxt] {
			break
		}
		arenas = append(arenas, nxt)
		visited[nxt] = true
		curr = nxt
	}
	return arenas, li, nil
}

// annotations returns a map keyed by USER POINTER (chunk_addr + 0x10) so
// callers walking heap chunks can look up the line where fd/bk live.
func (s *heapSnapshot) annotations() map[uint64]string {
	out := make(map[uint64]string)

	for i, chain := range s.tcache {
		for j, userPtr := range chain {
			out[userPtr] = fmt.Sprintf("tcache[idx=%d sz=0x%x][%d/%d]", i, tcacheChunkSize(i), j+1, s.tcacheCount[i])
		}
	}
	for i, chain := range s.fastbin {
		for j, chunkAddr := range chain {
			out[chunkAddr+chunkHeaderSize] = fmt.Sprintf("fastbin[idx=%d sz=0x%x][%d/%d]", i, fastbinChunkSize(i), j+1, len(chain))
		}
	}
	for i := 1; i < heapNBins; i++ {
		chain := s.binChain[i]
		if len(chain) == 0 {
			continue
		}
		for j, chunkAddr := range chain {
			var label string
			switch {
			case i == 1:
				label = fmt.Sprintf("unsorted[%d/%d]", j+1, len(chain))
			case i <= heapNSmallbins:
				label = fmt.Sprintf("small[idx=%d sz=0x%x][%d/%d]", i, i*heapMallocAlignment, j+1, len(chain))
			default:
				label = fmt.Sprintf("large[idx=%d][%d/%d]", i, j+1, len(chain))
			}
			out[chunkAddr+chunkHeaderSize] = label
		}
	}
	if s.state != nil && s.state.top != 0 {
		out[s.state.top+chunkHeaderSize] = "top"
	}
	return out
}

// ---- pretty printers ----------------------------------------------------

func (dbger *TypeDbg) printChunkChain(prefix string, chain []uint64) {
	if len(chain) == 0 {
		fmt.Printf("  %s(empty)\n", prefix)
		return
	}
	fmt.Printf("  %s", prefix)
	for i, addr := range chain {
		if i > 0 {
			fmt.Printf(" -> ")
		}
		fmt.Printf("%s0x%x%s", ColorCyan, addr, ColorReset)
	}
	fmt.Println()
}

func (dbger *TypeDbg) findMainHeap() (uint64, uint64, bool) {
	for _, p := range procMapsDetail {
		if strings.Contains(p.path, "[heap]") || p.path == "[heap]" {
			return p.start, p.end, true
		}
	}
	return 0, 0, false
}

// ---- commands -----------------------------------------------------------

func (dbger *TypeDbg) cmdBinsImpl() error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}

	arenas, li, err := dbger.listArenas()
	if err != nil {
		return err
	}
	mainArena := arenas[0]

	for arenaIdx, arenaAddr := range arenas {
		snap, err := dbger.snapshotArena(li, arenaAddr, mainArena)
		if err != nil {
			LogError("arena[%d] @ 0x%x: %v", arenaIdx, arenaAddr, err)
			continue
		}
		dbger.printArenaBins(arenaIdx, snap)
	}

	mmaps := dbger.findMmappedChunks(arenas)
	hLine("mmapped chunks")
	if len(mmaps) == 0 {
		fmt.Println("  (none)")
	} else {
		for i, addr := range mmaps {
			c, err := dbger.readChunk(addr)
			if err != nil {
				fmt.Printf("  [%d] %s0x%x%s  <unreadable: %v>\n", i, ColorRed, addr, ColorReset, err)
				continue
			}
			fmt.Printf("  [%d] chunk=%s0x%x%s  size=0x%x  user=%s0x%x%s\n",
				i, ColorCyan, addr, ColorReset,
				c.chunkSize(),
				ColorCyan, addr+chunkHeaderSize, ColorReset)
		}
	}
	hLineRaw()
	return nil
}

func (dbger *TypeDbg) printArenaBins(arenaIdx int, snap *heapSnapshot) {
	li := snap.libc
	ms := snap.state

	label := "main"
	if arenaIdx > 0 {
		label = fmt.Sprintf("thread #%d", arenaIdx)
	}
	hLine(fmt.Sprintf("arena[%d] %s (libc %s, addr=0x%x)", arenaIdx, label, li.version, snap.arena))

	if snap.heap != nil {
		fmt.Printf("  heap: %s0x%x%s - %s0x%x%s   top: %s0x%x%s   system_mem: 0x%x\n",
			ColorCyan, snap.heapStart, ColorReset,
			ColorCyan, snap.heapEnd, ColorReset,
			ColorCyan, ms.top, ColorReset,
			ms.systemMem)
	} else {
		fmt.Printf("  top: %s0x%x%s   system_mem: 0x%x   attached_threads: %d\n",
			ColorCyan, ms.top, ColorReset, ms.systemMem, ms.attachedThreads)
	}

	hLine("tcache")
	switch {
	case !li.hasTcache:
		fmt.Printf("  (libc %s has no tcache)\n", li.version)
	case snap.tcacheAddr == 0:
		fmt.Printf("  (tcache_perthread_struct not yet allocated in this arena)\n")
	default:
		fmt.Printf("  tcache_perthread_struct @ %s0x%x%s\n", ColorCyan, snap.tcacheAddr, ColorReset)
		any := false
		for i := 0; i < heapTcacheBins; i++ {
			if snap.tcacheCount[i] == 0 && len(snap.tcache[i]) == 0 {
				continue
			}
			any = true
			dbger.printChunkChain(
				fmt.Sprintf("tcache[idx=%d sz=0x%x][cnt=%d] -> ", i, tcacheChunkSize(i), snap.tcacheCount[i]),
				snap.tcache[i])
		}
		if !any {
			fmt.Println("  (all empty)")
		}
	}

	hLine("fastbin")
	any := false
	for i := 0; i < heapNFastbins; i++ {
		if len(snap.fastbin[i]) == 0 {
			continue
		}
		any = true
		dbger.printChunkChain(
			fmt.Sprintf("fastbin[idx=%d sz=0x%x] -> ", i, fastbinChunkSize(i)),
			snap.fastbin[i])
	}
	if !any {
		fmt.Println("  (all empty)")
	}

	hLine("unsorted")
	if len(snap.binChain[1]) == 0 {
		fmt.Println("  (empty)")
	} else {
		dbger.printChunkChain("unsorted -> ", snap.binChain[1])
	}

	hLine("smallbins")
	any = false
	for i := 2; i <= heapNSmallbins; i++ {
		if len(snap.binChain[i]) == 0 {
			continue
		}
		any = true
		dbger.printChunkChain(
			fmt.Sprintf("small[idx=%d sz=0x%x] -> ", i, i*heapMallocAlignment),
			snap.binChain[i])
	}
	if !any {
		fmt.Println("  (all empty)")
	}

	hLine("largebins")
	any = false
	for i := heapNSmallbins + 1; i < heapNBins; i++ {
		if len(snap.binChain[i]) == 0 {
			continue
		}
		any = true
		dbger.printChunkChain(
			fmt.Sprintf("large[idx=%d] -> ", i),
			snap.binChain[i])
	}
	if !any {
		fmt.Println("  (all empty)")
	}

	hLineRaw()
}

func (dbger *TypeDbg) cmdArena(_ interface{}) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}
	li, err := dbger.detectLibc()
	if err != nil {
		return err
	}
	mainArena, err := dbger.findMainArena(li)
	if err != nil {
		return err
	}

	hLine(fmt.Sprintf("arenas (libc %s)", li.version))
	visited := map[uint64]bool{}
	curr := mainArena
	idx := 0
	for curr != 0 && !visited[curr] && idx < 64 {
		visited[curr] = true
		ms, err := dbger.readMallocState(curr)
		if err != nil {
			fmt.Printf("  [%d] %s0x%x%s  <unreadable: %v>\n", idx, ColorRed, curr, ColorReset, err)
			break
		}
		label := "main"
		if curr != mainArena {
			label = "thread"
		}
		fmt.Printf("  [%d] %-7s @ %s0x%x%s  top=%s0x%x%s  system_mem=0x%x  attached=%d  next=0x%x\n",
			idx, label,
			ColorCyan, curr, ColorReset,
			ColorCyan, ms.top, ColorReset,
			ms.systemMem, ms.attachedThreads, ms.next)
		curr = ms.next
		idx++
	}
	hLineRaw()
	return nil
}

func (dbger *TypeDbg) cmdChunk(a interface{}) error {
	if !dbger.isStart {
		return errors.New("debuggee has not started")
	}
	args, ok := a.([]string)
	if !ok {
		return errors.New("invalid arguments")
	}
	addr, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	c, err := dbger.readChunk(addr)
	if err != nil {
		return err
	}
	flags := []string{}
	if c.prevInuse() {
		flags = append(flags, "PREV_INUSE")
	}
	if c.isMmapped() {
		flags = append(flags, "IS_MMAPPED")
	}
	if c.nonMainArena() {
		flags = append(flags, "NON_MAIN_ARENA")
	}
	flagStr := "-"
	if len(flags) > 0 {
		flagStr = strings.Join(flags, " | ")
	}

	fmt.Printf("chunk @ %s0x%x%s\n", ColorCyan, addr, ColorReset)
	fmt.Printf("  prev_size : %s0x%x%s\n", ColorCyan, c.prevSize, ColorReset)
	fmt.Printf("  size      : %s0x%x%s  (chunk=0x%x, flags=[%s])\n", ColorCyan, c.size, ColorReset, c.chunkSize(), flagStr)
	fmt.Printf("  fd        : %s0x%x%s\n", ColorCyan, c.fd, ColorReset)
	fmt.Printf("  bk        : %s0x%x%s\n", ColorCyan, c.bk, ColorReset)
	if c.chunkSize() >= heapMinLarge {
		fmt.Printf("  fd_nextsize: %s0x%x%s\n", ColorCyan, c.fdNS, ColorReset)
		fmt.Printf("  bk_nextsize: %s0x%x%s\n", ColorCyan, c.bkNS, ColorReset)
	}
	return nil
}
