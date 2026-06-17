CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(ARCH)-linux-gnu \
              -I/usr/include/bpf \
              -I.

.PHONY: all clean

all: escape_monitor.bpf.o

escape_monitor.bpf.o: escape_monitor.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
