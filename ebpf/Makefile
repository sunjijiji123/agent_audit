# eBPF Audit Build System

.PHONY: all clean

# Architecture detection
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  ARCH_FLAG := -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
  ARCH_FLAG := -D__TARGET_ARCH_arm64
else
  ARCH_FLAG :=
endif

# BPF program
BPF_SRC := audit.bpf.c
BPF_OBJ := audit.bpf.o

# C map reader tool
C_READER_SRC := bpf_map_dump.c
C_READER := bpf_map_dump

all: $(BPF_OBJ) $(C_READER)

$(BPF_OBJ): $(BPF_SRC)
	@echo "Building eBPF program $(BPF_SRC) -> $@ (arch=$(ARCH))"
	clang -g -O2 -target bpf $(ARCH_FLAG) -c $< -o $@
	-llvm-strip -g $@ 2>/dev/null || true

$(C_READER): $(C_READER_SRC)
	@echo "Building C map reader -> $@"
	gcc -O2 -o $@ $<

clean:
	rm -f $(BPF_OBJ) $(C_READER)
