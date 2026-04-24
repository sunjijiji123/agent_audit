# eBPF Audit Build System

.PHONY: all clean

# Architecture: arm64 or x86_64 (override with make ARCH=x86_64)
HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),aarch64)
    DEFAULT_ARCH := arm64
else ifeq ($(HOST_ARCH),x86_64)
    DEFAULT_ARCH := x86_64
else
    DEFAULT_ARCH := $(HOST_ARCH)
endif

ARCH ?= $(DEFAULT_ARCH)

# Map ARCH to clang target define
ifeq ($(ARCH),arm64)
    BPF_ARCH := arm64
    LIB_DIR  := /usr/lib/aarch64-linux-gnu
else ifeq ($(ARCH),x86_64)
    BPF_ARCH := x86
    LIB_DIR  := /usr/lib/x86_64-linux-gnu
else ifeq ($(ARCH),x86)
    BPF_ARCH := x86
    LIB_DIR  := /usr/lib/x86_64-linux-gnu
    ARCH     := x86_64
else
    $(error Unknown ARCH=$(ARCH). Supported: arm64, x86_64)
endif

# Cross-compile detection
CROSS_COMPILE ?=
ifeq ($(ARCH),$(DEFAULT_ARCH))
    # Native build
    CC := gcc
else ifeq ($(ARCH),x86_64)
    CC := x86_64-linux-gnu-gcc
else ifeq ($(ARCH),arm64)
    CC := aarch64-linux-gnu-gcc
endif

# Verify cross-compiler exists if needed
ifneq ($(ARCH),$(DEFAULT_ARCH))
    CC_CHECK := $(shell which $(CC) 2>/dev/null)
    ifeq ($(CC_CHECK),)
        $(error Cross-compiler $(CC) not found. Install gcc-$(ARCH)-linux-gnu)
    endif
endif

# BPF program
BPF_SRC := audit.bpf.c
BPF_OBJ := audit.bpf.o

# C map reader tool
C_READER_SRC := bpf_map_dump.c
C_READER := bpf_map_dump

# Loader shared library
LOADER_SRC := loader.c
LOADER_SO := loader.so

all: $(BPF_OBJ) $(C_READER) $(LOADER_SO)

$(BPF_OBJ): $(BPF_SRC)
	@echo "Building eBPF program $(BPF_SRC) -> $@ (arch=$(ARCH))"
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -c $< -o $@
	-llvm-strip -g $@ 2>/dev/null || true

$(C_READER): $(C_READER_SRC)
	@echo "Building C map reader -> $@ (arch=$(ARCH))"
	$(CC) -O2 -o $@ $<

$(LOADER_SO): $(LOADER_SRC)
	@echo "Building loader shared library -> $@ (arch=$(ARCH))"
	$(CC) -O2 -fPIC -shared -o $@ $< \
		$(LIB_DIR)/libbpf.a \
		$(LIB_DIR)/libelf.a \
		-lz -lpthread -static-libgcc

clean:
	rm -f $(BPF_OBJ) $(C_READER) $(LOADER_SO)
