BIN   := fastDbg
CAPS  := capstone/capstone/libcapstone.a

GOSRC := $(shell find . -name '*.go' \
            -not -path './findruction2/*' \
            -not -path './capstone/*')

CAPS  := capstone/capstone/libcapstone.a
EBPF  := trace.ebpf.o

.PHONY: all install clean vet test

all: $(BIN)

$(CAPS):
	$(MAKE) -C capstone/capstone
	@test -f $@ || (echo "capstone build did not produce $@" >&2; exit 1)

$(EBPF): ebpf/trace.ebpf.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
	  -I/usr/include/x86_64-linux-gnu -c $< -o $@

$(BIN): $(CAPS) $(EBPF) $(GOSRC)
	go build -o $@ .

install: $(BIN)
	sudo setcap cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin+eip $(BIN)

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -f $(BIN) $(EBPF)
	$(MAKE) -C capstone/capstone clean
