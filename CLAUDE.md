# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在本仓库中工作时提供指导。

**语言：请使用中文进行所有交流，但代码注释必须使用英文。**

## 知识库

Obsidian Vault 位于 `C:\Users\sun\Documents\Obsidian Vault`。开发相关的理解和决策记录在那里，遇到问题先查知识库。新发现及时写回对应的原子笔记。

## 项目概述

Agent Audit — 基于 eBPF 的进程审计工具，在内核层面监控 AI Agent 进程及其所有子进程。捕获 FILE（openat/read/write）、NET（connect）和 DNS（getaddrinfo）事件，输出结构化 JSONL 审计日志。

系统分三层：eBPF 内核程序（C）→ libbpf 加载器（共享库）→ Python 守护进程/CLI。Python 运行时**零外部依赖**（仅标准库）。

## 构建命令

**libbpf 版本: `1.4.0`（源码存于 `3rdp/libbpf/`，无需系统安装 libbpf-dev，编译时自动构建静态库）

```bash
# 本地构建（需要 clang/gcc/cmake/libelf/zlib）
./scripts/build.sh              # 当前架构
./scripts/build.sh x86_64       # 指定架构
./scripts/build.sh all          # 同时构建 x86_64 + arm64

# 仅构建 eBPF (CMake)
cd ebpf
cmake -S . -B build -DARCH=x86_64
make -C build                    # 生成 audit.bpf.o、loader.so

# 交叉编译
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=cmake/x86_64-linux-gnu.cmake
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-linux-gnu.cmake

# 清理
rm -rf ebpf/build
```

## 测试命令

测试需要在支持 BPF 的 Linux 机器上以 root 权限运行。无自动化测试框架。

```bash
sudo python3 test_e2e_cli.py       # FILE/NET/DNS 捕获验证
sudo python3 test_chain_depth.py   # 进程链追踪验证
```

## 开发用 CLI

```bash
sudo python3 -m cli.cli daemon start          # 启动审计守护进程
python3 -m cli.cli daemon stop                # 停止守护进程
python3 -m cli.cli audit add --process python3 --file '*'   # 添加监控目标
python3 -m cli.cli audit list                 # 查看监控目标
```

## 架构

```
内核 (audit.bpf.c)             用户态 C (loader.so)            用户态 Python
┌────────────────────┐         ┌─────────────────────┐        ┌──────────────────┐
│ 7 个 tracepoint +  │─maps──>│ libbpf 封装          │─ctypes─>│ daemon.py        │
│ 1 个 uprobe (DNS)  │         │ bpf_dump_events()   │  JSON  │ 轮询循环 → JSONL │
│ 4 张 BPF map       │         └─────────────────────┘        └──────────────────┘
└────────────────────┘
```

### BPF Maps

| Map | 类型 | 用途 |
|-----|------|------|
| `pid_whitelist` | HASH (1024) | 受监控的 PID，值 = `{root_pid, depth}` |
| `agent_tree` | HASH (2048) | 父子进程树，用于进程链重建，值 = `{parent_pid, comm, fork_time}` |
| `events` | LRU_HASH (65536) | 已捕获事件，key = `timestamp_ns`，通过 lookup-and-delete 消费 |
| `event_scratch` | PERCPU_ARRAY (1) | 每 CPU 临时缓冲区，避免 BPF 栈溢出 |

### 数据流

1. 系统调用触发 → BPF 查 `pid_whitelist` → 匹配则用 `event_scratch` 填充 `audit_event` 结构体 → 遍历 `agent_tree` 构建进程链（最多 8 级祖先，通过 `CHAIN_STEP` 宏展开，满足 BPF 验证器要求） → 插入 `events` map
2. Python 守护进程每 N 秒轮询 → `loader.so` 用 `bpf_map_lookup_and_delete_elem` 遍历 `events` map（破坏性读取）→ 通过 256KB 静态缓冲区返回 JSON 数组
3. Python 按 `ts_ns` 去重，从 `/proc/{pid}/` 补充信息（cmdline、exe、ppid），将 BPF 启动时间转换为 `"YYYY-MM-DD HH:MM:SS"` 格式，写入 JSONL

### 关键文件

- `ebpf/audit.bpf.c` — 所有内核钩子。`pack_process_chain()` 通过 `CHAIN_STEP` 宏实现有界循环展开（BPF 验证器要求）。fork 处理器自动将子进程加入白名单。
- `ebpf/loader.c` — 共享库导出 API：`bpf_load`、`bpf_unload`、`bpf_dump_events`、`bpf_map_update_pid_whitelist`、`bpf_map_update_agent_tree`。将二进制 `audit_event` 结构体序列化为 JSON（静态缓冲区）。
- `cli/agent_audit/bpf_loader.py` — 通过 ctypes 桥接 `loader.so`。`fetch_events()` 调用 `bpf_dump_events()` → `json.loads()`。
- `cli/agent_audit/bpf_reader.py` — 旧版备用方案，通过 `bpftool` 子进程工作。与 `bpf_loader.py` API 相同但未被实际导入。
- `cli/agent_audit/daemon.py` — fork 到后台，加载 BPF，进入轮询循环。使用 inotify 实现配置热更新。时间戳转换：`wall_ns = bpf_ts_ns + (time.time_ns() - CLOCK_BOOTTIME)`。
- `cli/agent_audit/config.py` — 原子化配置写入（临时文件 + 重命名）。配置发现顺序：`AGENT_AUDIT_CONFIG` 环境变量 > PyInstaller 包父目录 > 项目根目录。
- `cli/agent_audit/log_rotator.py` — 两个轮转日志器：`AuditLogger`（JSONL，50MB）和 `RuntimeLogger`（生命周期日志，10MB）。
- `cli/cli.py` — argparse CLI，子命令：`daemon start/stop/status`、`audit add/del/list`、`log --tail/--grep/--type`、`config`。

### 跨架构支持

- BPF 编译参数 `-D__TARGET_ARCH_x86` 或 `-D__TARGET_ARCH_arm64`（CO-RE）
- C loader 交叉编译使用 `x86_64-linux-gnu-gcc` 或 `aarch64-linux-gnu-gcc`
- Docker Buildx + QEMU 实现多架构 PyInstaller 打包
- 目标匹配方式：`--process`（精确 comm 名）或 `--processpath`（对 exe 路径做 fnmatch 通配）

## 行为准则

以下准则偏向谨慎而非速度。对于琐碎任务，请自行判断。

### 先思考再编码

- 明确陈述假设。不确定就问。
- 存在多种理解时，全部列出——不要悄悄选一个。
- 如果有更简单的方案，说出来。必要时提出反对。
- 遇到不清楚的地方，停下来问。

### 简单优先

- 不做超出需求的功能。
- 单次使用的代码不做抽象。
- 不对不可能发生的场景做错误处理。
- 如果你写了 200 行但 50 行就够了，重写。

### 精准修改

- 只改必须改的。匹配已有风格。
- 不要重构没坏的东西。
- 只删除因你的改动而变成废弃的 import/变量/函数。
- 每一行变更都应该能追溯到用户的需求。

### 目标驱动

- 将任务转化为可验证的目标和明确的成功标准。
- 多步骤任务先列出计划，标注每步的验证点。
- 循环直到验证通过。

## DAS-DS 日志格式示例

FILE open 事件示例：
```json
{
  "eventType": "fileEvent",
  "rawLogNum": 120003,
  "logType": "file",
  "opType": "open",
  "localTime": "2025-12-23 10:57:29",
  "unixTime": 1734940649,
  "logfuzId": "",
  "processId": "12345",
  "image": "/usr/bin/python3.10",
  "commandLine": "python3 script.py",
  "processUserName": "root",
  "processMd5": "",
  "processName": "python3",
  "parentProcessName": "bash",
  "processGuid": "",
  "traceId": "",
  "parentProcessGuid": "",
  "parentProcessId": "1000",
  "filePath": "/root/script.py",
  "fileSize": 1024,
  "fileType": "",
  "modifyTime": "2025-12-20 15:30:00",
  "fileMd5": "",
  "createTime": "",
  "targetFilename": ""
}
```

字段说明：
- `localTime`: `"YYYY-MM-DD HH:MM:SS"` 格式（空格分隔，无时区后缀）
- `filePath`: 仅文件路径（目录和符号链接被过滤）
- `processId`/`parentProcessId`: **字符串格式**（如 `"12345"`，不是整数）
- `fileSize/fileType/modifyTime`: 仅 FILE open 事件（read/write 不采集）
- `processMd5/logfuzId`: 空字符串（计算 deferred）
- `currentDirectory`: 不存在（已删除字段）
