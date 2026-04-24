#!/bin/bash
# ============================================
# Docker 构建入口脚本
# ============================================

set -e

echo "========================================"
echo "🔨 Agent Audit - 单文件 CLI 构建"
echo "========================================"
echo "架构: $(uname -m)"
echo "Python: $(python --version)"
echo "PyInstaller: $(pyinstaller --version)"
echo ""

# 检查 loader.so 是否存在
if [ ! -f "ebpf/loader.so" ]; then
    echo "⚠️  ebpf/loader.so 不存在，尝试编译..."
    if [ -f "ebpf/loader.c" ]; then
        echo "编译 libbpf loader..."
        # 这里需要 libbpf 开发环境，实际构建时要先编译
        echo "注意：loader.so 需要提前编译好，放到 ebpf/ 目录下"
    fi
fi

# 安装 Python 依赖
echo "📦 安装 Python 依赖..."
pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

# 构建
echo "🚀 PyInstaller 构建中..."
pyinstaller --clean agent-audit.spec

echo ""
echo "✅ 构建完成！"
echo "   产物: dist/agent-audit"
echo "   大小: $(du -h dist/agent-audit | cut -f1)"
echo ""

# 验证产物
if [ -f "dist/agent-audit" ]; then
    echo "🔍 验证可执行文件..."
    file dist/agent-audit
    ldd dist/agent-audit 2>/dev/null | head -5
fi

echo ""
echo "========================================"
