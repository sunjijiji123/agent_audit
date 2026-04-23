#!/usr/bin/env python3
"""性能对比测试：CO-RE Loader vs bpftool 方案"""

import json
import os
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from cli.agent_audit.bpf_loader import (
    load_bpf, unload_bpf, register_pid, fetch_events, loader_available
)


def run_command(cmd, timeout=30):
    """运行命令并返回输出和耗时"""
    start = time.time()
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start
        return {
            "success": result.returncode == 0,
            "elapsed": elapsed,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "elapsed": timeout, "error": "timeout"}


def test_bpf_load_performance(iterations=5):
    """测试 BPF 加载时间"""
    print("\n" + "=" * 60)
    print("BPF 加载性能测试")
    print("=" * 60)

    results = {"core_loader": [], "bpftool": []}

    # 测试 CO-RE Loader
    print("\n[CO-RE Loader] 加载测试...")
    for i in range(iterations):
        unload_bpf()  # 确保之前已卸载
        time.sleep(0.2)

        start = time.time()
        success = load_bpf()
        elapsed = time.time() - start

        if success:
            results["core_loader"].append(elapsed)
            print(f"  第 {i+1}/{iterations} 次: {elapsed*1000:.2f}ms")
        else:
            print(f"  第 {i+1}/{iterations} 次: 失败")
        unload_bpf()
        time.sleep(0.2)

    # 测试 bpftool 方案
    print("\n[bpftool] 加载测试...")
    pin_dir = "/sys/fs/bpf/audit_test"
    bpf_obj = "ebpf/audit.bpf.o"

    for i in range(iterations):
        subprocess.run(["rm", "-rf", pin_dir], capture_output=True)
        subprocess.run(["mkdir", "-p", pin_dir], capture_output=True)
        time.sleep(0.2)

        start = time.time()
        result = run_command(
            f"bpftool prog loadall {bpf_obj} {pin_dir}/audit autoattach"
        )
        elapsed = time.time() - start

        if result["success"]:
            results["bpftool"].append(elapsed)
            print(f"  第 {i+1}/{iterations} 次: {elapsed*1000:.2f}ms")
        else:
            print(f"  第 {i+1}/{iterations} 次: 失败")

        subprocess.run(["rm", "-rf", pin_dir], capture_output=True)
        time.sleep(0.2)

    return results


def test_event_fetch_performance(iterations=10, events_per_round=50):
    """测试事件导出性能"""
    print("\n" + "=" * 60)
    print("事件导出性能测试")
    print("=" * 60)

    results = {"core_loader": [], "bpftool": []}

    # 测试 CO-RE Loader
    print("\n[CO-RE Loader] 事件导出测试...")
    load_bpf()
    my_pid = os.getpid()
    register_pid(my_pid, my_pid, 0)

    for i in range(iterations):
        # 先生成一些事件
        for j in range(events_per_round):
            with open(f"/tmp/evt_{i}_{j}.txt", "w") as f:
                f.write(f"test {i} {j}")

        time.sleep(0.05)  # 等待事件进入 map

        start = time.time()
        events = fetch_events()
        elapsed = time.time() - start

        results["core_loader"].append({
            "elapsed": elapsed,
            "event_count": len(events)
        })
        print(f"  第 {i+1}/{iterations} 次: {len(events)} 个事件, {elapsed*1000:.2f}ms")

    unload_bpf()

    # 清理临时文件
    for f in Path("/tmp").glob("evt_*.txt"):
        f.unlink()

    return results


def test_memory_usage():
    """测试内存占用"""
    print("\n" + "=" * 60)
    print("内存占用测试")
    print("=" * 60)

    results = {}

    # 测试 CO-RE Loader
    print("\n[CO-RE Loader] 内存测试...")
    tracemalloc.start()

    load_bpf()
    my_pid = os.getpid()
    register_pid(my_pid, my_pid, 0)

    # 生成并导出一些事件
    for i in range(100):
        with open(f"/tmp/mem_test_{i}.txt", "w") as f:
            f.write("x")
    fetch_events()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    unload_bpf()

    results["core_loader"] = {"current_mb": current / 1024 / 1024, "peak_mb": peak / 1024 / 1024}
    print(f"  当前: {current/1024/1024:.2f} MB")
    print(f"  峰值: {peak/1024/1024:.2f} MB")

    # 清理
    for f in Path("/tmp").glob("mem_test_*.txt"):
        f.unlink()

    return results


def calculate_stats(numbers):
    """计算统计值"""
    if not numbers:
        return {"count": 0, "avg": 0, "min": 0, "max": 0}
    return {
        "count": len(numbers),
        "avg": sum(numbers) / len(numbers),
        "min": min(numbers),
        "max": max(numbers),
    }


def print_summary(load_results, fetch_results, memory_results):
    """打印汇总报告"""
    print("\n" + "=" * 60)
    print("性能对比汇总报告")
    print("=" * 60)

    # BPF 加载时间
    print("\n📊 BPF 加载时间对比:")
    core_times = load_results["core_loader"]
    bpftool_times = load_results["bpftool"]

    if core_times and bpftool_times:
        core_stats = calculate_stats(core_times)
        bpftool_stats = calculate_stats(bpftool_times)

        print(f"\n  {'指标':<15} {'CO-RE Loader':>15} {'bpftool':>15} {'提升':>10}")
        print("  " + "-" * 58)
        print(f"  {'平均 (ms)':<15} {core_stats['avg']*1000:>15.2f} {bpftool_stats['avg']*1000:>15.2f}")
        print(f"  {'最快 (ms)':<15} {core_stats['min']*1000:>15.2f} {bpftool_stats['min']*1000:>15.2f}")
        print(f"  {'最慢 (ms)':<15} {core_stats['max']*1000:>15.2f} {bpftool_stats['max']*1000:>15.2f}")

        speedup = ((bpftool_stats['avg'] - core_stats['avg']) / bpftool_stats['avg'] * 100)
        print(f"\n  🚀 CO-RE Loader 比 bpftool 快 {speedup:.1f}%")
    else:
        print("  数据不足（某个方案加载失败）")

    # 事件导出性能
    print("\n" + "-" * 60)
    print("\n📊 事件导出性能对比 (10次测试):")

    if fetch_results["core_loader"]:
        core_elapsed = [r["elapsed"] for r in fetch_results["core_loader"]]
        core_counts = [r["event_count"] for r in fetch_results["core_loader"]]

        elapsed_stats = calculate_stats(core_elapsed)
        count_stats = calculate_stats(core_counts)

        print(f"\n  [CO-RE Loader]")
        print(f"    平均导出时间: {elapsed_stats['avg']*1000:.2f}ms")
        print(f"    平均事件数: {count_stats['avg']:.1f} 个")
        if count_stats['avg'] > 0:
            print(f"    平均单事件耗时: {elapsed_stats['avg']/count_stats['avg']*1000000:.2f}μs")

    # 内存占用
    print("\n" + "-" * 60)
    print("\n📊 内存占用对比:")

    if "core_loader" in memory_results:
        core_mem = memory_results["core_loader"]
        print(f"\n  [CO-RE Loader]")
        print(f"    峰值内存: {core_mem['peak_mb']:.2f} MB")
        print(f"    当前内存: {core_mem['current_mb']:.2f} MB")

    print("\n" + "=" * 60)
    print("✅ 性能测试完成")
    print("=" * 60)


def main():
    print("=" * 60)
    print("CO-RE Loader vs bpftool 性能对比测试")
    print("=" * 60)

    # 检查 CO-RE Loader 是否可用
    if not loader_available():
        print("❌ CO-RE Loader 不可用，请检查 loader.so 是否存在")
        return 1

    print(f"✅ CO-RE Loader 可用，开始测试...")

    # 运行各项测试
    load_results = test_bpf_load_performance(iterations=5)
    fetch_results = test_event_fetch_performance(iterations=10)
    memory_results = test_memory_usage()

    # 打印汇总
    print_summary(load_results, fetch_results, memory_results)

    # 保存结果到文件
    results = {
        "load": load_results,
        "fetch": fetch_results,
        "memory": memory_results,
        "timestamp": time.time()
    }

    with open("performance_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n💾 详细结果已保存到 performance_results.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
