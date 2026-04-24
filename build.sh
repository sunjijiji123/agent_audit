#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCH="${1:-$(uname -m)}"

case "$ARCH" in
    aarch64|arm64) ARCH=arm64 ;;
    x86_64|amd64)  ARCH=x86_64 ;;
    all)
        echo "========================================"
        echo "  Agent Audit - Multi-Arch Build"
        echo "========================================"
        echo ""
        echo "[INFO] Building arm64..."
        "$SCRIPT_DIR/build.sh" arm64 || true
        echo ""
        echo "[INFO] Building x86_64..."
        "$SCRIPT_DIR/build.sh" x86_64 || true
        echo ""
        echo "========================================"
        echo "[OK] Multi-arch build complete!"
        echo "========================================"
        exit 0
        ;;
esac

echo "========================================"
echo "  Agent Audit - Build ($ARCH)"
echo "========================================"
echo ""

"$SCRIPT_DIR/scripts/build_ebpf.sh" "$ARCH"
echo ""
"$SCRIPT_DIR/scripts/build_pyinstaller.sh" "$ARCH"
echo ""
"$SCRIPT_DIR/scripts/build_tar.sh" "$ARCH"

echo ""
echo "========================================"
echo "[OK] Build complete ($ARCH)!"
echo "========================================"
