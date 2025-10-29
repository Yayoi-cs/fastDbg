package ebpf

/*
#cgo LDFLAGS: -lbpf -lelf -lz
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>

struct event {
    unsigned int pid;
    unsigned long long syscall;
};

// Helper function to setup perf_event_attr (avoids union/field issues)
static void setup_perf_attr(struct perf_event_attr *attr) {
    memset(attr, 0, sizeof(*attr));
    attr->type = PERF_TYPE_SOFTWARE;
    attr->size = sizeof(*attr);
    attr->config = PERF_COUNT_SW_BPF_OUTPUT;
    attr->sample_period = 1;
    attr->wakeup_events = 1;
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                          int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int read_perf_event(int fd, void *buf, size_t size) {
    struct {
        struct perf_event_header header;
        char data[256];
    } e;

    int ret = read(fd, &e, sizeof(e));
    if (ret <= 0) return ret;

    if (e.header.type == PERF_RECORD_SAMPLE) {
        memcpy(buf, e.data, size);
        return size;
    }
    return 0;
}
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

var MapFlag bool = false

type Tracer struct {
	pid    int
	obj    *C.struct_bpf_object
	links  []*C.struct_bpf_link
	perfFd C.int
	stop   chan struct{}
}

func NewTrace(pid int) (*Tracer, error) {
	t := &Tracer{
		pid:  pid,
		stop: make(chan struct{}),
	}

	objPath := C.CString("trace.ebpf.o")
	defer C.free(unsafe.Pointer(objPath))

	t.obj = C.bpf_object__open(objPath)
	if t.obj == nil {
		return nil, fmt.Errorf("failed to open BPF object")
	}

	if C.bpf_object__load(t.obj) != 0 {
		C.bpf_object__close(t.obj)
		return nil, fmt.Errorf("failed to load BPF object")
	}

	progMmap := C.bpf_object__find_program_by_name(t.obj, C.CString("trace_mmap"))
	progBrk := C.bpf_object__find_program_by_name(t.obj, C.CString("trace_brk"))

	if progMmap == nil || progBrk == nil {
		t.Close()
		return nil, fmt.Errorf("failed to find BPF programs")
	}

	linkMmap := C.bpf_program__attach(progMmap)
	linkBrk := C.bpf_program__attach(progBrk)

	if linkMmap == nil || linkBrk == nil {
		t.Close()
		return nil, fmt.Errorf("failed to attach BPF programs")
	}
	t.links = append(t.links, linkMmap, linkBrk)

	eventsMap := C.bpf_object__find_map_by_name(t.obj, C.CString("events"))
	if eventsMap == nil {
		t.Close()
		return nil, fmt.Errorf("failed to find events map")
	}
	mapFd := C.bpf_map__fd(eventsMap)

	// Use C helper function instead of accessing fields directly
	var attr C.struct_perf_event_attr
	C.setup_perf_attr(&attr)

	t.perfFd = C.perf_event_open(&attr, -1, 0, -1, 0)
	if t.perfFd < 0 {
		t.Close()
		return nil, fmt.Errorf("failed to open perf event")
	}

	cpu := C.int(0)
	if C.bpf_map_update_elem(mapFd, unsafe.Pointer(&cpu), unsafe.Pointer(&t.perfFd), 0) != 0 {
		t.Close()
		return nil, fmt.Errorf("failed to update BPF map")
	}

	go t.eventLoop()

	return t, nil
}

func (t *Tracer) eventLoop() {
	buf := make([]byte, 256)
	for {
		select {
		case <-t.stop:
			return
		default:
			ret := C.read_perf_event(t.perfFd, unsafe.Pointer(&buf[0]), 256)
			if ret > 0 {
				var event struct {
					Pid     uint32
					Syscall uint64
				}
				event.Pid = *(*uint32)(unsafe.Pointer(&buf[0]))
				event.Syscall = *(*uint64)(unsafe.Pointer(&buf[4]))

				if int(event.Pid) == t.pid {
					fmt.Printf("EBPF DETECT MAPPING")
					MapFlag = true
				}
			}
		}
	}
}

func (t *Tracer) Close() {
	close(t.stop)

	if t.perfFd >= 0 {
		syscall.Close(int(t.perfFd))
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
