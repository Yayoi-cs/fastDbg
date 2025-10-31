
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

struct event {
    __u32 pid;
    __u64 syscall; // 9=mmap, 12=brk
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(void *ctx) {
    struct event e = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .syscall = 9
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int trace_brk(void *ctx) {
    struct event e = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .syscall = 12
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
