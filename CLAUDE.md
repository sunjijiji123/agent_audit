# AI eBPF Agent Audit

## 项目背景

审计 AI Agent 操作行为的 eBPF 进程审计系统。核心需求：监控 Agent 进程的文件访问、网络连接、DNS 查询，并沿进程链追踪子进程/孙子进程的行为。

## 架构

```
内核态 (BPF tracepoint/uprobe)
  → LRU_HASH map (events)
    → 用户态 Python daemon (poll + filter + JSONL)
```

- BPF 程序: `ebpf/audit.bpf.c` — 捕获 openat/connect/getaddrinfo
- C 加速读取: `ebpf/bpf_map_dump.c` — 替代 bpftool dump
- 用户态过滤: `cli/agent_audit/matcher.py` — comm + 规则匹配
- 守护进程: `cli/agent_audit/daemon.py` — 加载 BPF、轮询、写日志
- 配置: `config.json` — targets 规则 + 日志/daemon 参数
- 远程开发: SSH root@192.168.5.137, 代码在 /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli

## 已确认的设计决策

### 内核态白名单过滤 (L1 - comm 级别)

当前 BPF 全量采集所有进程事件，用户态过滤丢弃 99.1%（实测），存在：
- LRU map 被噪音挤满，有用事件被挤出丢失
- 内核→用户态数据拷贝浪费
- Python 解析/匹配无用事件浪费 CPU

**方案：** 在 BPF 程序中加入 comm whitelist map，不匹配的进程直接 return 0，不写入 events map。

```c
// comm 白名单 map (L1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, __u32);  // placeholder / 未来 L2 bitmask
} comm_whitelist SEC(".maps");
```

白名单通过 bpftool map update 更新（验证阶段），daemon inotify 检测 config 变更后同步更新 whitelist map。

**✓ 已完成 (2026-04-22): 内核态 comm 白名单过滤验证**

**实现内容：**
1. BPF 程序修改 (`ebpf/audit.bpf.c`):
   - 新增 `comm_whitelist` map (HASH, max_entries: 256)
   - 三个 syscall handlers (openat/connect/getaddrinfo) 在 entry 点检查白名单
   - 不匹配的进程直接 `return 0`，不产生事件

2. Daemon 修改 (`cli/agent_audit/daemon.py` + `bpf_reader.py`):
   - `get_whitelist_map_id()`：查找 whitelist map ID
   - `update_whitelist_map()`：写入白名单条目 (使用 bpftool hex 格式)
   - `sync_whitelist_to_bpf()`：从 config 同步白名单到 BPF map
   - 启动时自动同步 + config reload 时更新

**验证结果：**
- **噪音削减效果：** 100% 有效 - events map 只包含白名单进程
- **实测数据：** 625 个事件，全部来自 3 个白名单进程 (python3: 511, bash: 96, ls: 18)
- **对比 Phase 0：** 原用户态过滤丢弃 99.1%，现内核态过滤直达目标进程
- **Config reload：** 正常工作 - 添加 "cat" 目标后 whitelist 正确更新
- **空白名单安全：** Daemon 检测到无启用目标时 abort 并报错："No enabled targets in config"

**编译注意事项：**
- 需使用 `-D__TARGET_ARCH_x86` 编译标志 (Makefile 已配置)
- BPF handlers 调用两次 `bpf_get_current_comm()` (一次检查 whitelist，一次写入 event)
- bpftool map update 使用 hex 格式：`key 0x70 0x79... value 0 0 0 0`

**下一步优化方向：**
- Phase 2 (P1): PID 级过滤 + 进程链追踪 (解决同名进程问题)
- Phase 3 (P2): CO-RE 可移植性改造 + libbpf loader

## 待办事项

### P0: 内核态 comm 白名单过滤
- 修改 audit.bpf.c：添加 comm_whitelist map，在每个 handler 中检查
- Python daemon：启动时从 config 提取 comm 列表写入 whitelist map
- Config reload 时同步更新 whitelist map
- 实测验证噪音削减比例（对照当前 99.1%）

### P1: PID 级过滤 + 内核态进程链追踪

**核心决策：**
- PID 过滤（不是 comm）：解决同名进程问题
- 只缓存 Agent 进程树：只审计 Agent 操作，空间小
- 实时监控进程退出：立即清理缓存，防止脏数据和 PID 复用风险

#### 内核态数据结构

```
┌─── Kernel BPF Maps ────────────────────────────────────────┐
│                                                            │
│  pid_whitelist (HASH, max_entries: 1024)                   │
│    key: u32 pid                                            │
│    value: struct whitelist_entry {                         │
│      u32 root_pid;        // Agent 根进程 PID              │
│      u64 register_time;   // 注册时间（防 PID 复用）        │
│      u8  depth;           // 进程树深度                     │
│    }                                                       │
│                                                            │
│  agent_tree (HASH, max_entries: 2048)                      │
│    key: u32 pid                                            │
│    value: struct tree_node {                               │
│      u32 parent_pid;      // 父进程 PID（必在 whitelist）  │
│      char comm[16];       // 进程名                        │
│      u64 fork_time;       // fork 时间                     │
│    }                                                       │
│    → 只缓存 Agent 进程树，不缓存系统进程                   │
│                                                            │
│  events (LRU_HASH, max_entries: 65536)                     │
│    key: u64 timestamp_ns                                   │
│    value: struct audit_event {                             │
│      u32 type, pid, ts_ns;                                 │
│      u8  chain_depth;                                      │
│      struct chain_node chain[8];  // 内核态直接查询打包    │
│      char data[256];                                       │
│    }                                                       │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

#### Tracepoint handlers

```
sched_process_fork:
  parent_pid → 查 pid_whitelist
    ├─ 在 whitelist → child_pid 加入：
    │   ├─ pid_whitelist[child] = {root_pid: parent.root_pid, depth: parent.depth+1}
    │   ├─ agent_tree[child] = {parent_pid, comm: "forked", fork_time}
    │   └─ agent_children[parent].child_pids[] += child
    └─ 不在 → 跳过（不缓存系统进程）

sched_process_exec:
  pid → 查 pid_whitelist
    ├─ 在 whitelist → 更新 agent_tree[pid].comm = current_comm
    └─ 不在 → 跳过

sched_process_exit:
  pid → 查 pid_whitelist
    ├─ 在 whitelist → 清理：
    │   ├─ 删除 pid_whitelist[pid]
    │   ├─ 删除 agent_tree[pid]
    │   ├─ 查 agent_children[pid] → 遍历 child_pids → 删除每个子进程
    │   └─ 删除 agent_children[pid]
    └─ 不在 → 跳过
```

#### Syscall handler（内核态查询进程链）

```
openat/connect/getaddrinfo:
  pid → 查 pid_whitelist
    ├─ 不在 → return 0（过滤）
    └─ 在 → 从 agent_tree 递归查询进程链
         ├─ 从当前 pid → parent_pid → parent_pid...
         ├─ 最多追溯 8 层到 entry.root_pid
         ├─ 到达 root_pid 后停止（不追溯 systemd/sshd 等）
         └─ chain 直接打包到 event struct
```

**审计范围：** 只监控 Agent 进程树，进程链追溯到 Agent root_pid 结束，不追溯更上层系统进程。

**生命周期管理：** Exit 时通过 agent_children 双向索引递归清理所有子进程，防止孤儿进程缓存。

**PID 复用防护：** 依赖 sched_process_exit 实时清理，竞态窗口极小（微秒级），Agent 进程数有限，复用概率低。

### P1: 进程链追踪与子进程缓存
- 需要监听进程创建事件（如 tracepoint/sched/sched_process_fork）
- 内核态缓存父子关系，自动将 Agent 子进程纳入审计范围
- 用户态已有 _build_proc_chain()（读 /proc），需内核态补充 fork 追踪

### P2: CO-RE 化改造（分发的必要前提）

**当前不可移植问题：**

| 问题 | 现状 | 影响 |
|------|------|------|
| BPF 对象绑定 | `#include <linux/bpf.h>` 绑定编译时内核头文件 | .o 只能在同版本内核加载 |
| 手写寄存器 | `struct pt_regs { ... x86_64 }` | ARM64 不兼容 |
| 硬编码路径 | `SEC("uprobe/lib/x86_64-linux-gnu/libc.so.6:...")` | Ubuntu 22.04 专属，Fedora/Alpine 不同 |
| 废弃 API | `bpf_probe_read()` | 新内核推荐 `bpf_probe_read_kernel/user()` |

**CO-RE 方案：**
- 引入 vmlinux.h + BPF_CORE_READ（编译时记录 BTF 重定位信息）
- 加载时 libbpf 根据目标内核 BTF 自动调整字段偏移
- .bpf.o 成为通用对象，支持 5.4+ 内核（BTF 可用）

**内核版本底线：**
- 5.4+: BTF 可用（`/sys/kernel/btf/vmlinux`）→ CO-RE 最低要求
- 5.14+: uprobe auto-attach via SEC() name → 更干净的 DNS 捕获
- RHEL 8 (4.18): 不行，太老无 BTF
- RHEL 9 (5.14): 刚好达标
- Ubuntu 20.04 (5.4): 最低线
- Ubuntu 22.04 (5.15+): OK
- 测试机 6.8: 完全没问题

### P2: 生产化替代 bpftool

**bpftool 问题：**
- 依赖目标机器装了 bpftool 且版本兼容
- 仅用于开发验证，不适合生产分发

**方案：** 内嵌 libbpf C loader（替代 bpftool loadall + map 操作）
- 单个 C 程序负责：加载 BPF + 读 map + update whitelist
- bpf_map_dump.c 已是正确方向，需扩展为完整 loader
- 或 Python ctypes 直接调用 bpf() syscall（更轻量）

### P2: 可分发打包

**目标形态：**
```
ai-ebpf-agent-audit/          # pip install 包
├── ebpf/
│   └── audit.bpf.o           # CO-RE 编译的 BPF 对象（通用）
├── cli/
│   └── agent_audit/
│       ├── daemon.py          # 主程序
│       ├── bpf_loader.py      # libbpf 加载器（替代 bpftool）
│       ├── matcher.py
│       └── ...
├── config.json
└── setup.py / pyproject.toml
```

**glibc uprobe 路径发现：**
- 当前硬编码：`lib/x86_64-linux-gnu/libc.so.6`（Ubuntu 22.04）
- 运行时发现：`ldd --version` 或读 `/etc/ld.so.cache` 找 libc
- musl/Alpine 无 glibc：DNS uprobe 需降级或跳过

**最终效果：** pip install 一行装好，自动适配目标内核和 libc

## 远程 Linux 调试与验证

**开发环境：**
- SSH: root@192.168.5.137 (Ubuntu 22.04, Kernel 6.8)
- 代码目录: /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli
- 免密登录已配置，直接执行命令即可

### BPF 程序编译与加载

```bash
# 编译 BPF 程序
ssh root@192.168.5.137 "cd /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli && clang -target bpf -c ebpf/audit.bpf.c -o ebpf/audit.bpf.o -g"

# 加载 BPF 程序
ssh root@192.168.5.137 "bpftool prog loadall /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli/ebpf/audit.bpf.o /sys/fs/bpf/audit/audit autoattach"

# 查看 BPF maps
ssh root@192.168.5.137 "bpftool -j map show | grep -A5 'comm_whitelist\|pid_whitelist\|events'"

# Dump events map
ssh root@192.168.5.137 "bpftool map dump name events"

# 清空 map
ssh root@192.168.5.137 "bpftool map delete id <map_id> key hex <key_hex>"
```

### Daemon 启动与日志

```bash
# 启动 daemon
ssh root@192.168.5.137 "cd /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli && python3 -m cli.agent_audit start"

# 停止 daemon
ssh root@192.168.5.137 "cd /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli && python3 -m cli.agent_audit stop"

# 查看审计日志
ssh root@192.168.5.137 "tail -f /var/log/agent-audit/audit.log"

# 查看运行时日志
ssh root@192.168.5.137 "tail -f /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli/logs/runtime.log"

# 检查 daemon PID
ssh root@192.168.5.137 "cat /root/tmp/agent-audit-daemon.pid && ps -p <pid>"
```

### 功能验证测试

```bash
# Phase 1: Comm whitelist 验证
ssh root@192.168.5.137 "cd /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli && python3 test_comm_whitelist.py"

# Phase 2: PID whitelist + 进程链验证
ssh root@192.168.5.137 "cd /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli && python3 test_pid_whitelist.py"

# 触发测试进程
ssh root@192.168.5.137 "python3 -c 'import os; os.system(\"ls /tmp\")'"  # 测试 python3→ls 链

# 检查 events map 大小
ssh root@192.168.5.137 "bpftool map dump name events | wc -l"

# 性能对比（Phase 0 vs Phase 1 vs Phase 2）
ssh root@192.168.5.137 "cd /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli && python3 measure_noise_reduction.py"
```

### BPF 程序调试

```bash
# 查看 BPF verifier log
ssh root@192.168.5.137 "bpftool prog loadall ebpf/audit.bpf.o /sys/fs/bpf/test --log-level 2"

# 查看 BPF tracepoint attach 状态
ssh root@192.168.5.137 "bpftool prog show"

# 手动触发 tracepoint 测试
ssh root@192.168.5.137 "cat /sys/kernel/debug/tracing/trace"

# 查看 BPF program ID
ssh root@192.168.5.137 "bpftool -j prog show | jq '.[] | select(.name | contains(\"audit\"))'"

# 查看 BPF map ID
ssh root@192.168.5.137 "bpftool -j map show | jq '.[] | select(.name | contains(\"whitelist\"))'"
```

### CO-RE 兼容性测试

```bash
# 生成 vmlinux.h
ssh root@192.168.5.137 "bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h"

# 编译 CO-RE BPF
ssh root@192.168.5.137 "clang -target bpf -g -DBPF_CORE_READ -c ebpf/audit.bpf.c -o ebpf/audit_core.bpf.o"

# 验证 BTF relocation info
ssh root@192.168.5.137 "bpftool btf show file ebpf/audit_core.bpf.o"

# 测试跨内核版本（需虚拟机）
# Ubuntu 20.04 VM (kernel 5.4): scp audit_core.bpf.o to VM, load
# Fedora VM (kernel 5.14+): scp audit_core.bpf.o to VM, load
# Alpine container (musl): docker run -it alpine, test libc discovery
```

### 常见问题排查

**问题 1: BPF map 查询失败**
```bash
# 检查 map ID
ssh root@192.168.5.137 "bpftool map show"

# 检查 daemon 写入的 map_id
ssh root@192.168.5.137 "cat /mnt/hgfs/code/1-ai/ai-ebpf-demo-cli/config.json | jq '.daemon.bpf_map_id'"
```

**问题 2: 进程链断层**
```bash
# 检查 agent_tree map
ssh root@192.168.5.137 "bpftool map dump name agent_tree"

# 检查 pid_whitelist map
ssh root@192.168.5.137 "bpftool map dump name pid_whitelist"

# 手动注册 PID
ssh root@192.168.5.137 "bpftool map update name pid_whitelist key 4 1000 value 0 0"
```

**问题 3: CO-RE 加载失败**
```bash
# 检查 BTF 可用性
ssh root@192.168.5.137 "ls /sys/kernel/btf/vmlinux"

# 检查内核版本
ssh root@192.168.5.137 "uname -r"

# 检查 libbpf 版本
ssh root@192.168.5.137 "dpkg -l | grep libbpf"
```

### 测试脚本模板

```python
# test_comm_whitelist.py
import subprocess
import json

# 1. 配置 whitelist
config = {"targets": [{"process": "python3", "enabled": True}]}
subprocess.run(["python3", "-c", f"import json; json.dump({config}, open('config.json','w'))"])

# 2. 启动 daemon
subprocess.run(["python3", "-m", "cli.agent_audit", "start"])

# 3. 触发 syscall
subprocess.run(["python3", "-c", "open('/tmp/test.txt', 'w').write('test')"])

# 4. 等待并检查 audit.log
import time; time.sleep(3)
log = subprocess.run(["tail", "-5", "/var/log/agent-audit/audit.log"], capture_output=True)
events = [json.loads(line) for line in log.stdout.splitlines()]

# 5. 验证
assert len(events) > 0, "No events captured"
assert events[-1]["comm"] == "python3", "Wrong process captured"
assert "FILE" in events[-1]["type"], "Wrong event type"

print("✓ Comm whitelist test passed")
```

# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.
