#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${1:-$(uname -m)}"

case "$ARCH" in
    aarch64|arm64) ARCH=arm64 ;;
    x86_64|amd64)  ARCH=x86_64 ;;
esac

echo "[STEP] Building eBPF programs (arch=$ARCH)..."
cd "$PROJECT_ROOT/ebpf"
make clean ARCH="$ARCH"
make ARCH="$ARCH"

echo "[OK] eBPF build complete ($ARCH)"
echo "  audit.bpf.o  -> $PROJECT_ROOT/ebpf/audit.bpf.o"
echo "  loader.so    -> $PROJECT_ROOT/ebpf/loader.so"
echo "  bpf_map_dump -> $PROJECT_ROOT/ebpf/bpf_map_dump"
