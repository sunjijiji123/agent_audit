#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${1:-$(uname -m)}"

case "$ARCH" in
    aarch64|arm64) ARCH=arm64 ;;
    x86_64|amd64)  ARCH=x86_64 ;;
esac

HOST_ARCH=$(uname -m)
case "$HOST_ARCH" in
    aarch64|arm64) HOST_ARCH=arm64 ;;
    x86_64|amd64)  HOST_ARCH=x86_64 ;;
esac

if [ "$ARCH" != "$HOST_ARCH" ]; then
    echo "[WARN] Cross-building PyInstaller for $ARCH on $HOST_ARCH is not supported directly."
    echo "       Please run build_pyinstaller.sh on a $ARCH machine, or use Docker."
    exit 1
fi

echo "[STEP] PyInstaller build (arch=$ARCH)..."
cd "$PROJECT_ROOT"
rm -rf dist/ build/
pyinstaller --clean agent-audit.spec

# Copy install/uninstall scripts into the bundle
cp install.sh uninstall.sh dist/agent_audit/
chmod +x dist/agent_audit/install.sh dist/agent_audit/uninstall.sh

# Remove stale config.json from bundle (config lives outside)
rm -f dist/agent_audit/_internal/config.json

# Move to arch-specific directory
mkdir -p "dist/$ARCH"
mv dist/agent_audit "dist/$ARCH/"

echo "[OK] PyInstaller build complete ($ARCH)"
echo "  Output: $PROJECT_ROOT/dist/$ARCH/agent_audit/"
