package ebpf

/*
#cgo LDFLAGS: -lbpf -lelf -lz
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct event {
    unsigned int pid;
    unsigned long long syscall;
};

void handleEvent(void *ctx, int cpu, void *data, unsigned int size);
void handleLost(void *ctx, int cpu, unsigned long long lost_cnt);
*/
import "C"

import (
	"fmt"
	"golang.org/x/sys/unix"
	"sync"
	"sync/atomic"
	"unsafe"
)

var MapFlag bool = false
var tracerRegistry sync.Map
var nextTracerID atomic.Int64

type Tracer struct {
	id    int64
	pid   int
	obj   *C.struct_bpf_object
	links []*C.struct_bpf_link
	pb    *C.struct_perf_buffer
	stop  chan struct{}
	wg    sync.WaitGroup
}

//export handleEvent
func handleEvent(ctx unsafe.Pointer, cpu C.int, data unsafe.Pointer, size C.uint) {
	tracerID := int64(uintptr(ctx))

	val, ok := tracerRegistry.Load(tracerID)
	if !ok {
		return
	}
	t := val.(*Tracer)

	event := (*C.struct_event)(data)

	if int(event.pid) == t.pid {
		syscallNum := uint64(event.syscall)
		if syscallNum == unix.SYS_MMAP || syscallNum == unix.SYS_BRK || syscallNum == unix.SYS_MUNMAP {
			MapFlag = true
		}
	}
}

//export handleLost
func handleLost(ctx unsafe.Pointer, cpu C.int, lostCnt C.ulonglong) {
	fmt.Printf("Lost %d events on CPU %d\n", lostCnt, cpu)
}

func NewTrace(pid int) (*Tracer, error) {
	t := &Tracer{
		id:   nextTracerID.Add(1),
		pid:  pid,
		stop: make(chan struct{}),
	}

	tracerRegistry.Store(t.id, t)

	objPath := C.CString("trace.ebpf.o")
	defer C.free(unsafe.Pointer(objPath))

	t.obj = C.bpf_object__open(objPath)
	if t.obj == nil {
		tracerRegistry.Delete(t.id)
		return nil, fmt.Errorf("failed to open BPF object")
	}

	if C.bpf_object__load(t.obj) != 0 {
		C.bpf_object__close(t.obj)
		tracerRegistry.Delete(t.id)
		return nil, fmt.Errorf("failed to load BPF object")
	}

	progMmapName := C.CString("trace_mmap")
	progBrkName := C.CString("trace_brk")
	defer C.free(unsafe.Pointer(progMmapName))
	defer C.free(unsafe.Pointer(progBrkName))

	progMmap := C.bpf_object__find_program_by_name(t.obj, progMmapName)
	progBrk := C.bpf_object__find_program_by_name(t.obj, progBrkName)

	if progMmap == nil || progBrk == nil {
		t.Close()
		return nil, fmt.Errorf("failed to find BPF programs")
	}

	linkMmap := C.bpf_program__attach(progMmap)
	if linkMmap == nil {
		t.Close()
		return nil, fmt.Errorf("failed to attach trace_mmap program")
	}
	t.links = append(t.links, linkMmap)

	linkBrk := C.bpf_program__attach(progBrk)
	if linkBrk == nil {
		t.Close()
		return nil, fmt.Errorf("failed to attach trace_brk program")
	}
	t.links = append(t.links, linkBrk)

	eventsMapName := C.CString("events")
	defer C.free(unsafe.Pointer(eventsMapName))

	eventsMap := C.bpf_object__find_map_by_name(t.obj, eventsMapName)
	if eventsMap == nil {
		t.Close()
		return nil, fmt.Errorf("failed to find events map")
	}
	mapFd := C.bpf_map__fd(eventsMap)

	ctx := unsafe.Pointer(uintptr(t.id))

	t.pb = C.perf_buffer__new(
		mapFd,
		8,
		C.perf_buffer_sample_fn(unsafe.Pointer(C.handleEvent)),
		C.perf_buffer_lost_fn(unsafe.Pointer(C.handleLost)),
		ctx, // Pass ID as "pointer" - it's really just an integer
		nil,
	)
	if t.pb == nil {
		t.Close()
		return nil, fmt.Errorf("failed to create perf buffer")
	}

	t.wg.Add(1)
	go t.pollLoop()

	return t, nil
}

func (t *Tracer) pollLoop() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stop:
			return
		default:
			ret := C.perf_buffer__poll(t.pb, 100)
			if ret < 0 && ret != -4 {
				fmt.Printf("Error polling perf buffer: %d\n", ret)
			}
		}
	}
}

func (t *Tracer) Close() {
	close(t.stop)
	t.wg.Wait()
	tracerRegistry.Delete(t.id)

	if t.pb != nil {
		C.perf_buffer__free(t.pb)
	}

	for _, link := range t.links {
		if link != nil {
			C.bpf_link__destroy(link)
		}
	}

	if t.obj != nil {
		C.bpf_object__close(t.obj)
	}
}

func ResetFlag() {
	MapFlag = false
}
