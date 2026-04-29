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
rm -rf build
if [ "$ARCH" = "arm64" ]; then
    cmake -S . -B build -DARCH=arm64
else
    cmake -S . -B build -DARCH=x86_64
fi
make -C build

# 复制产物到 ebpf 根目录，保持与旧脚本一致的输出位置
cp build/audit.bpf.o build/loader.so . 2>/dev/null || true

echo "[OK] eBPF build complete ($ARCH)"
echo "  audit.bpf.o  -> $PROJECT_ROOT/ebpf/audit.bpf.o"
echo "  loader.so    -> $PROJECT_ROOT/ebpf/loader.so"
