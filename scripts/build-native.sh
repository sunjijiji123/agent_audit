#!/bin/bash
# Native build script for eBPF audit agent
# Builds directly on the host machine without Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Building eBPF Audit Agent (Native) ==="
echo "Project root: $PROJECT_ROOT"

# Check dependencies
echo ""
echo "Checking dependencies..."
if ! command -v clang &> /dev/null; then
    echo "ERROR: clang not found. Please install clang."
    exit 1
fi
if ! command -v gcc &> /dev/null; then
    echo "ERROR: gcc not found. Please install gcc."
    exit 1
fi
if ! command -v make &> /dev/null; then
    echo "ERROR: make not found. Please install make."
    exit 1
fi

# Check for libbpf headers
if [ ! -f /usr/include/bpf/bpf.h ]; then
    echo "WARNING: libbpf headers not found at /usr/include/bpf/"
    echo "         Please install libbpf-devel or libbpf-dev"
fi

# Build
echo ""
echo "Building BPF program and tools..."
cd "$PROJECT_ROOT/ebpf"
make clean
make

echo ""
echo "=== Build Complete ==="
echo ""
echo "Output files:"
echo "  - ebpf/audit.bpf.o        (BPF program)"
echo "  - ebpf/bpf_map_dump       (C map reader, dynamic link)"
echo "  - ebpf/bpf_map_dump-static (C map reader, static link)"
echo ""
echo "Next steps:"
echo "  1. Run: sudo python3 -m cli.agent_audit start"
echo "  2. Or install: sudo scripts/install.sh"
