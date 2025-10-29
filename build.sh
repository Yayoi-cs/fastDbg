clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c ebpf/trace.ebpf.c -o trace.ebpf.o
go build .
sudo setcap cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin+eip fastDbg
