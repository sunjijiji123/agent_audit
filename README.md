# Agent Audit

基于 eBPF 的进程审计工具，在内核层面监控进程及其子进程，捕获 FILE/NET/DNS 事件，输出结构化 JSONL 审计日志。

## 特性

- **短生命周期进程实时匹配**: exec 时自动加入白名单，捕获 curl/wget 等短生命周期进程 (< 100ms)
- **进程链追踪**: 自动重建父子进程关系，最多支持 8 级进程链
- **零外部依赖**: Python 运行时仅依赖标准库，libbpf 静态链接
- **Config 热更新**: inotify 监听配置变更，无需重启
- **DAS-DS 格式**: 结构化 JSONL 日志，符合 DAS-DS 规范
- **跨架构支持**: x86_64 / arm64 (aarch64)

## 架构

```
内核 (audit.bpf.c)          用户态 C (loader.so)        用户态 Python
┌─────────────────┐         ┌──────────────────┐       ┌──────────────┐
│ tracepoint:     │─maps──> │ libbpf skeleton  │─ctypes─>│ daemon.py    │
│ - openat/read   │         │ bpf_dump_events  │  JSON  │ 轮询 → JSONL │
│ - connect       │         │ map operations   │        │ CLI          │
│ uprobe: DNS     │         └──────────────────┘       └──────────────┘
└─────────────────┘
```

## 技术栈

- **eBPF**: Linux Kernel ≥ 4.18, BPF CO-RE (Compile Once, Run Everywhere)
- **C**: libbpf 1.4.0 (静态链接), CMake 构建系统
- **Python**: Python 3.8+ (仅标准库), ctypes BPF 桥接, PyInstaller 打包

## 安装

### 从发布包安装

```bash
# 解压发布包
tar -xzf agent-audit-linux-x86_64.tar.gz
cd agent_audit

# 安装到系统
sudo ./install.sh

# 启动守护进程
sudo agent_audit daemon start
```

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/sunjijiji123/agent_audit.git
cd agent_audit

# 构建 eBPF + loader (需要 clang/cmake/libelf/zlib)
./scripts/build.sh x86_64

# 构建 PyInstaller 打包版本
./scripts/build_pyinstaller.sh

# 安装
sudo bash dist/x86_64/agent_audit/install.sh
```

## 使用

### CLI 命令

```bash
# 守护进程管理
sudo agent_audit daemon start     # 启动守护进程
sudo agent_audit daemon stop      # 停止守护进程
agent_audit daemon status         # 查看状态

# 监控目标配置
agent_audit audit add --process curl --network '*'    # 添加监控目标
agent_audit audit del --process curl                  # 删除监控目标
agent_audit audit list                                # 查看监控列表

# 日志查询
agent_audit log --tail 50                             # 查看最近 50 条日志
agent_audit log --grep curl                           # 搜索包含 curl 的日志
agent_audit log --type network                        # 查看网络事件日志

# 配置文件路径
agent_audit config                                    # 显示配置文件路径
```

### 配置文件

配置文件位于 `/usr/local/agent_audit/config.json`:

```json
{
  "targets": [
    {
      "id": 1,
      "process": "curl",
      "network": ["*"],
      "enabled": true
    }
  ],
  "log": {
    "path": "/var/log/agent-audit/audit.log",
    "max_size_mb": 50,
    "backup_count": 5
  },
  "daemon": {
    "poll_interval_sec": 2,
    "bpf_elf": "ebpf/audit.bpf.o"
  }
}
```

**配置字段说明**:
- `process`: 进程名精确匹配 (comm, 16 字符)
- `processpath`: 可执行路径通配匹配 (fnmatch)
- `file/network/dns`: 事件过滤规则 (预留字段，当前未实现过滤逻辑)
- `enabled`: 是否启用该监控目标

### 日志输出

日志文件: `/var/log/agent-audit/audit.log` (JSONL 格式)

**事件类型**:
- `fileEvent`: FILE open/read/write 事件
- `networkConnect`: NET connect 事件
- `dnsQuery`: DNS getaddrinfo 查询
- `processCreate`: FORK 进程创建

**示例日志** (curl 网络连接):
```json
{
  "eventType": "networkConnect",
  "logType": "network",
  "opType": "connect",
  "localTime": "2026-04-29 17:22:25",
  "unixTime": 1777454545,
  "processId": "126553",
  "processName": "curl",
  "image": "/usr/bin/curl",
  "commandLine": "curl -v http://example.com",
  "destAddress": "93.184.216.34",
  "destPort": 80,
  "transProtocol": "TCP"
}
```

## 运行要求

- **操作系统**: Linux (Ubuntu 22.04+ / Debian 12+ / CentOS 8+)
- **内核版本**: ≥ 4.18 (BPF CO-RE 支持)
- **权限**: root (CAP_BPF + CAP_NET_ADMIN)
- **架构**: x86_64 / arm64

## 开发

### 项目结构

```
agent_audit/
├── ebpf/
│   ├── audit.bpf.c          # BPF 内核程序
│   ├── loader.c             # libbpf loader 共享库
│   ├── loader.h             # loader API 头文件
│   └── CMakeLists.txt       # CMake 构建配置
├── cli/
│   ├── agent_audit/
│   │   ├── daemon.py        # 守护进程主逻辑
│   │   ├── bpf_loader.py    # ctypes BPF 桥接
│   │   ├── config.py        # 配置文件读写
│   │   └── log_rotator.py   # 日志轮转
│   └── cli.py               # CLI 入口
├── scripts/
│   ├── build.sh             # eBPF 构建脚本
│   ├── build_pyinstaller.sh # PyInstaller 打包脚本
│   └ build_tar.sh           # 发布包打包脚本
└── config.json              # 默认配置文件
```

### 构建命令

```bash
# 构建 eBPF + loader
./scripts/build.sh              # 当前架构
./scripts/build.sh x86_64       # x86_64 架构
./scripts/build.sh arm64        # arm64 架构
./scripts/build.sh all          # 同时构建两种架构

# 构建 PyInstaller 打包
./scripts/build_pyinstaller.sh

# 创建发布包
./scripts/build_tar.sh
```

### 测试

测试需要在支持 BPF 的 Linux 机器上以 root 权限运行：

```bash
sudo python3 test_e2e_cli.py       # FILE/NET/DNS 捕获验证
sudo python3 test_chain_depth.py   # 进程链追踪验证
```

## 许可证

GPL-2.0

## 作者

sunjijiji123