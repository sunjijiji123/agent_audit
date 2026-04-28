# ============================================
# Docker 多架构 PyInstaller 构建环境
# 支持: linux/amd64, linux/arm64
# ============================================

ARG PYTHON_VERSION=3.10

FROM python:${PYTHON_VERSION}-slim

LABEL maintainer="agent-audit-builder"

# 安装构建依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    patchelf \
    binutils \
    libc6-dev \
    upx-ucl \
    cmake \
    make \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
RUN pip install --no-cache-dir \
    pyinstaller

# 设置工作目录
WORKDIR /build

# 入口脚本
COPY scripts/build-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/build-entrypoint.sh

ENTRYPOINT ["build-entrypoint.sh"]
