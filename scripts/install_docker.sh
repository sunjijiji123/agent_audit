#!/bin/bash
# ============================================
# Docker 环境配置脚本
# ============================================
# 用法：sudo ./install_docker.sh
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Docker + QEMU 多架构环境配置脚本                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# 检查是否为root
if [ "$EUID" -ne 0 ]; then
    log_error "请使用 sudo 运行此脚本"
    exit 1
fi

log_info "步骤 1: 清理apt锁..."
pkill -9 apt || true
pkill -9 dpkg || true
sleep 1
rm -f /var/lib/dpkg/lock* /var/cache/apt/archives/lock
dpkg --configure -a

log_info "步骤 2: 更新软件源..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

log_info "步骤 3: 安装 Docker..."
apt-get install -y docker.io

log_info "步骤 4: 启动 Docker 服务..."
systemctl start docker
systemctl enable docker

log_info "步骤 5: 验证 Docker 安装..."
docker --version
docker info | head -10

log_info "步骤 6: 安装 QEMU 多架构支持..."
docker run --privileged --rm tonistiigi/binfmt --install all

log_info "步骤 7: 验证多架构支持..."
docker buildx version
docker run --rm --platform linux/arm64 alpine uname -m || log_warn "ARM64 测试失败（可能需要重启 Docker）"

echo ""
echo "════════════════════════════════════════════════════════════════"
log_info "Docker 环境配置完成！"
echo "════════════════════════════════════════════════════════════════"
echo ""
log_info "下一步操作:"
echo "  cd /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli"
echo "  ./build.sh              # 构建双架构 (x86_64 + arm64)"
echo "  ./build.sh x86_64       # 只构建 x86_64"
echo "  ./build.sh arm64        # 只构建 arm64"
echo ""
log_info "测试构建结果:"
echo "  ./dist/agent-audit-x86_64 --help"
echo "  sudo ./test_complete_audit.py"
echo ""