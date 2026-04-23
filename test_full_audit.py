#!/usr/bin/env python3
"""完整的端到端审计功能测试"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cli.agent_audit.bpf_loader import (
    load_bpf, unload_bpf, register_pid, fetch_events
)


def run_cmd(cmd):
    """运行 shell 命令"""
    subprocess.run(cmd, shell=True, capture_output=True)


def trigger_file_events():
    """触发各种文件事件"""
    print("  📁 触发文件事件...")

    # 文件创建/写
    with open("/tmp/test_create.txt", "w") as f:
        f.write("hello world\n")

    # 文件读
    with open("/tmp/test_create.txt", "r") as f:
        f.read()

    # 文件追加
    with open("/tmp/test_create.txt", "a") as f:
        f.write("append line\n")

    # 文件夹访问
    os.listdir("/var/log/")

    # 文件重命名
    run_cmd("mv /tmp/test_create.txt /tmp/test_renamed.txt")

    # 权限修改
    os.chmod("/tmp/test_renamed.txt", 0o755)

    # 文件删除
    os.unlink("/tmp/test_renamed.txt")

    # 创建临时目录
    os.makedirs("/tmp/test_dir", exist_ok=True)
    os.rmdir("/tmp/test_dir")


def trigger_network_events():
    """触发网络事件"""
    print("  🌐 触发网络事件...")
    try:
        import socket

        # TCP 连接
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(("1.1.1.1", 53))
        except:
            pass
        finally:
            s.close()

        # UDP 连接
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(b"test", ("8.8.8.8", 53))
        except:
            pass
        finally:
            s.close()
    except:
        pass


def trigger_dns_events():
    """触发 DNS 查询事件"""
    print("  🔍 触发 DNS 查询事件...")
    try:
        import socket
        socket.gethostbyname("example.com")
        socket.gethostbyname("google.com")
    except:
        pass


def trigger_process_chain():
    """触发进程链"""
    print("  🔗 触发进程链...")

    # bash -> python -> ls
    subprocess.run(
        ["bash", "-c", "ls /tmp > /dev/null"],
        capture_output=True
    )

    # 嵌套调用
    subprocess.run(
        ["bash", "-c", "python3 -c \"import os; os.system('echo test')\""],
        capture_output=True
    )


def print_event_summary(events):
    """打印事件汇总"""
    event_types = {}
    comms = set()
    max_chain = 0

    for e in events:
        t = e.get("type", "UNKNOWN")
        event_types[t] = event_types.get(t, 0) + 1
        comms.add(e.get("comm", ""))
        chain_depth = e.get("chain_depth", 0)
        if chain_depth > max_chain:
            max_chain = chain_depth

    print(f"\n📊 事件汇总:")
    print(f"  总事件数: {len(events)}")
    print(f"  进程名称: {', '.join(comms)}")
    print(f"  最大进程链深度: {max_chain}")
    print(f"\n  按类型统计:")
    for t, count in sorted(event_types.items()):
        print(f"    {t:10s}: {count} 个")


def print_event_details(events, limit=10):
    """打印事件详情"""
    print(f"\n📋 事件详情 (前 {limit} 个):")
    print("-" * 80)

    for i, e in enumerate(events[:limit]):
        event_type = e.get("type", "UNKNOWN")
        pid = e.get("pid", 0)
        comm = e.get("comm", "")
        data = e.get("data", "")
        chain = e.get("chain", [])

        chain_str = " -> ".join([f"{c.get('comm', '')}" for c in chain])
        if chain_str:
            chain_str = f" [chain: {chain_str}]"

        print(f"  [{i+1}] {event_type:8s} pid={pid:5d} {comm:12s} {data[:50]}{chain_str}")


def main():
    print("=" * 60)
    print("🔍 完整端到端审计功能测试")
    print("=" * 60)

    # 清理
    print("\n🧹 清理旧的 BPF 实例...")
    unload_bpf()
    time.sleep(0.5)

    # 加载 BPF
    print("\n🚀 加载 BPF 程序...")
    if not load_bpf():
        print("❌ BPF 加载失败！")
        return 1
    print("   ✅ BPF 加载成功")

    # 注册当前进程
    my_pid = os.getpid()
    print(f"\n📝 注册测试进程 PID: {my_pid}")
    if not register_pid(my_pid, my_pid, 0):
        print("❌ PID 注册失败！")
        unload_bpf()
        return 1
    print("   ✅ PID 注册成功")

    # 触发各类事件
    print("\n⚡ 开始触发审计事件...")
    trigger_file_events()
    trigger_network_events()
    trigger_dns_events()
    trigger_process_chain()

    # 等待事件流入 map
    print("\n⏳ 等待事件流入 BPF map...")
    time.sleep(1.0)

    # 导出并验证事件
    print("\n📥 从 BPF map 导出事件...")
    events = fetch_events()

    print_event_summary(events)
    print_event_details(events)

    # 验证结果
    print("\n✅ 测试验证:")
    file_ok = any(e.get("type") == "FILE" for e in events)
    net_ok = any(e.get("type") == "NETWORK" for e in events)
    dns_ok = any(e.get("type") == "DNS" for e in events)

    print(f"  文件事件: {'✅' if file_ok else '❌'}")
    print(f"  网络事件: {'✅' if net_ok else '❌'}")
    print(f"  DNS 事件: {'✅' if dns_ok else '❌'}")

    # 检查进程链
    has_chain = any(e.get("chain_depth", 0) > 0 for e in events)
    print(f"  进程链: {'✅' if has_chain else '⚠️'} (深度>0)")

    # 保存结果
    with open("test_audit_results.json", "w") as f:
        json.dump(events, f, indent=2, default=str)
    print(f"\n💾 完整结果已保存到 test_audit_results.json")

    # 清理
    unload_bpf()

    print("\n" + "=" * 60)
    if file_ok and net_ok and dns_ok:
        print("🎉 所有测试通过！")
    else:
        print("⚠️ 部分测试未通过，请检查输出")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
