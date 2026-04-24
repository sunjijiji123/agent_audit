#!/bin/bash
# ============================================
# Agent Audit - 一键多架构构建脚本
# ============================================
# 用法：
#   ./build.sh              # 默认：编译 x86_64 + arm64 双架构
#   ./build.sh x86_64       # 只编译 x86_64
#   ./build.sh arm64        # 只编译 arm64
# ============================================

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Agent Audit - 多架构单文件 CLI 构建工具                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    log_error "Docker 未安装，请先安装 Docker"
    log_info "Ubuntu 安装命令: apt-get install -y docker.io"
    exit 1
fi

# 检查 Docker Buildx 支持
if ! docker buildx version &> /dev/null; then
    log_error "Docker Buildx 不支持，请升级 Docker"
    exit 1
fi

# 检查 QEMU 多架构支持
if ! docker run --rm tonistiigi/binfmt --version &> /dev/null; then
    log_warn "QEMU 未安装，正在安装多架构支持..."
    docker run --privileged --rm tonistiigi/binfmt --install all
    log_info "QEMU 安装完成"
fi

# 参数解析：默认双架构
ARCHES=${1:-"x86_64 arm64"}
OUTPUT_DIR="dist"

log_info "目标架构: $ARCHES"
log_info "输出目录: $OUTPUT_DIR"
echo ""

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

# 为每个架构构建
for arch in $ARCHES; do
    echo ""
    log_step "═══════════════════════════════════════════"
    log_step "构建架构: $arch"
    log_step "═══════════════════════════════════════════"
    echo ""

    # 转换 Docker 平台名称
    case $arch in
        x86_64|amd64)
            PLATFORM="linux/amd64"
            ;;
        arm64|aarch64)
            PLATFORM="linux/arm64"
            ;;
        *)
            log_error "不支持的架构: $arch"
            continue
            ;;
    esac

    log_info "Docker 平台: $PLATFORM"

    # 使用 Buildx 构建
    log_info "开始构建（这可能需要 5-10 分钟）..."
    docker buildx build \
        --platform "$PLATFORM" \
        --output "type=local,dest=$OUTPUT_DIR/$arch" \
        -f Dockerfile.builder \
        .

    if [ $? -eq 0 ]; then
        log_info "架构 $arch 构建成功!"

        # 重命名产物
        if [ -f "$OUTPUT_DIR/$arch/dist/agent-audit" ]; then
            mv "$OUTPUT_DIR/$arch/dist/agent-audit" "$OUTPUT_DIR/agent-audit-$arch"
            chmod +x "$OUTPUT_DIR/agent-audit-$arch"

            # 清理临时目录
            rm -rf "$OUTPUT_DIR/$arch"

            log_info "产物: $OUTPUT_DIR/agent-audit-$arch"

            # 验证架构和大小
            if command -v file &> /dev/null; then
                file_info=$(file "$OUTPUT_DIR/agent-audit-$arch")
                log_info "文件信息: $file_info"
            fi

            size=$(du -h "$OUTPUT_DIR/agent-audit-$arch" | cut -f1)
            log_info "文件大小: $size"
        else
            log_error "产物未找到: $OUTPUT_DIR/$arch/dist/agent-audit"
        fi
    else
        log_error "架构 $arch 构建失败!"
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════════"
log_info "构建完成！产物列表:"
ls -lh "$OUTPUT_DIR"/agent-audit-* 2>/dev/null || echo "  (无产物)"
echo "════════════════════════════════════════════════════════════════"
echo ""
log_info "使用方法:"
echo "  sudo ./dist/agent-audit-x86_64 daemon start    # x86_64 系统"
echo "  sudo ./dist/agent-audit-arm64 daemon start     # ARM64 系统"
echo ""
log_info "CLI 命令示例:"
echo "  ./dist/agent-audit-x86_64 audit add --process python3 --file '*'"
echo "  ./dist/agent-audit-x86_64 audit list"
echo "  ./dist/agent-audit-x86_64 daemon start"
echo ""
