#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

ARCH="${1:-$(uname -m)}"
case "$ARCH" in
    aarch64|arm64) ARCH=arm64 ;;
    x86_64|amd64)  ARCH=x86_64 ;;
esac

TAR_NAME="agent-audit-linux-${ARCH}.tar.gz"

if [ ! -d "dist/$ARCH/agent_audit" ]; then
    echo "[ERROR] dist/$ARCH/agent_audit/ not found. Run build_pyinstaller.sh first."
    exit 1
fi

echo "[STEP] Creating tarball (arch=$ARCH)..."
rm -f "$TAR_NAME"
tar czf "$TAR_NAME" -C "dist/$ARCH" agent_audit

echo "[OK] Tarball created: $TAR_NAME"
ls -lh "$TAR_NAME"
sha256sum "$TAR_NAME"
