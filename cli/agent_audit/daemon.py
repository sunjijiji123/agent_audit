"""Daemon runner — loads BPF, polls map, filters events, writes JSONL."""

import os
import sys
import time
import signal
import json
from pathlib import Path
from typing import Optional, Set, Dict, Any

from .config import load_config, save_config
from .bpf_reader import load_bpf, get_map_id, fetch_events, deduplicate_events, unload_bpf, clear_map
from .matcher import filter_events
from .log_rotator import make_audit_logger

_PID_FILE = "/root/tmp/agent-audit-daemon.pid"
_CONFIG_PATH = str(Path(__file__).resolve().parent.parent.parent / "config.json")
_PIN_DIR = "/sys/fs/bpf/audit"

_run_loop_flag = True
_logger: Optional[object] = None


# ── PID file ────────────────────────────────────────────────────────────────────

def _write_pid() -> None:
    with open(_PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))


def _read_pid() -> Optional[int]:
    try:
        with open(_PID_FILE, encoding="utf-8") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def _remove_pid() -> None:
    try:
        os.unlink(_PID_FILE)
    except FileNotFoundError:
        pass


# ── DaemonRunner ───────────────────────────────────────────────────────────────

class DaemonRunner:
    def start(self) -> None:
        pid = _read_pid()
        if pid and os.path.exists(f"/proc/{pid}"):
            print(f"Daemon already running (PID {pid})", file=sys.stderr)
            sys.exit(1)

        pid = os.fork()
        if pid > 0:
            time.sleep(0.5)
            actual = _read_pid()
            if actual and os.path.exists(f"/proc/{actual}"):
                print(f"Daemon started (PID {actual})")
            else:
                print("Daemon may have failed — check log")
            return

        os.setsid()
        fd = os.open(os.devnull, os.O_RDWR)
        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        if fd > 2:
            os.close(fd)

        _write_pid()
        run_loop()

    def stop(self) -> None:
        pid = _read_pid()
        if not pid or not os.path.exists(f"/proc/{pid}"):
            print("Daemon not running")
            _remove_pid()
            return
        os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            if not os.path.exists(f"/proc/{pid}"):
                break
            time.sleep(0.1)
        _remove_pid()
        print("Daemon stopped")


# ── signal handler ─────────────────────────────────────────────────────────────

def _sig_handler(signum, frame) -> None:
    global _run_loop_flag
    _run_loop_flag = False


# ── inotify ───────────────────────────────────────────────────────────────────

def _setup_inotify(config_path: str) -> Optional[int]:
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fd = libc.inotify_init1(0x00000800)
        if fd == -1:
            return None
        wd = libc.inotify_add_watch(fd, config_path.encode(), 0x00000002 | 0x00000008)
        if wd == -1:
            os.close(fd)
            return None
        return fd
    except (OSError, AttributeError):
        return None


# ── run_loop ───────────────────────────────────────────────────────────────────

def run_loop() -> None:
    """Load BPF, poll map, filter events, write JSONL audit log."""
    global _run_loop_flag, _logger

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    cfg = load_config(_CONFIG_PATH)
    log_cfg = cfg.get("log", {})
    log_path = log_cfg.get("path", "/var/log/agent-audit/audit.log")
    max_size_mb = log_cfg.get("max_size_mb", 50)
    backup_count = log_cfg.get("backup_count", 5)
    poll_interval = cfg.get("daemon", {}).get("poll_interval_sec", 2)
    bpf_elf = cfg.get("daemon", {}).get("bpf_elf", "")

    if not bpf_elf or not os.path.exists(bpf_elf):
        print(f"BPF ELF not found: {bpf_elf}", file=sys.stderr)
        return

    _logger = make_audit_logger(log_path, max_size_mb, backup_count)
    inotify_fd = _setup_inotify(_CONFIG_PATH)
    last_inotify_check = 0.0

    # ── Load BPF program ──────────────────────────────────────────────
    targets = cfg.get("targets", [])
    process_names = [t["process"] for t in targets if t.get("enabled", True)]

    if load_bpf(bpf_elf, _PIN_DIR):
        _logger.log_event({"event": "bpf_loaded", "elf": bpf_elf, "targets": process_names})
    else:
        _logger.log_event({"event": "bpf_load_failed", "elf": bpf_elf})
        _logger.close()
        return

    map_id = get_map_id()
    if map_id < 0:
        _logger.log_event({"event": "map_id_not_found"})
        _logger.close()
        return

    # Save map_id to config for reference
    cfg.setdefault("daemon", {})["bpf_map_id"] = map_id
    save_config(cfg, _CONFIG_PATH)

    # Clear existing entries so we start fresh
    clear_map(map_id)

    _logger.log_event({"event": "daemon_started", "map_id": map_id})

    seen_events: Set[int] = set()

    def _get_process_info(pid: int) -> Dict[str, Any]:
        """读取进程详细信息（cmdline, exe, cwd）."""
        info = {}
        try:
            # cmdline
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().decode("utf-8", errors="replace").split("\x00")
                info["cmdline"] = cmdline[0] if cmdline else ""

            # exe
            exe = os.readlink(f"/proc/{pid}/exe")
            info["exe"] = exe

            # cwd (working directory)
            cwd = os.readlink(f"/proc/{pid}/cwd")
            info["cwd"] = cwd

            # ppid (parent pid)
            with open(f"/proc/{pid}/stat", "r") as f:
                stat = f.read().split()
                info["ppid"] = int(stat[3]) if len(stat) > 3 else 0
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            # 进程已退出或无法访问
            pass
        return info

    def _aggregate_by_process(events):
        """按 (pid, comm) 聚合事件，输出进程为主体的日志条目."""
        from collections import defaultdict
        groups = defaultdict(lambda: {"file_reads": [], "connects": [], "dns_queries": []})
        process_info_cache = {}  # 缓存进程信息

        for event in events:
            key = (event["pid"], event["comm"])
            groups[key]["pid"] = event["pid"]
            groups[key]["comm"] = event["comm"]
            etype = event.get("type", "")
            data = event.get("data", "")
            if etype == "FILE" and data:
                groups[key]["file_reads"].append(data)
            elif etype == "NET" and data:
                groups[key]["connects"].append(data)
            elif etype == "DNS" and data:
                groups[key]["dns_queries"].append(data)

        result = []
        from datetime import datetime
        now = datetime.now().isoformat()

        for (pid, comm), val in groups.items():
            # 获取进程信息（每个 pid 只查询一次）
            if pid not in process_info_cache:
                process_info_cache[pid] = _get_process_info(pid)
            proc_info = process_info_cache[pid]

            entry = {
                "ts": now,
                "pid": pid,
                "comm": comm,
            }

            # 添加进程详细信息
            if proc_info.get("cmdline"):
                entry["cmdline"] = proc_info["cmdline"]
            if proc_info.get("exe"):
                entry["exe"] = proc_info["exe"]
            if proc_info.get("cwd"):
                entry["cwd"] = proc_info["cwd"]
            if proc_info.get("ppid"):
                entry["ppid"] = proc_info["ppid"]

            # 添加事件数据
            if val["file_reads"]:
                entry["file_reads"] = val["file_reads"]
            if val["connects"]:
                entry["connects"] = val["connects"]
            if val["dns_queries"]:
                entry["dns_queries"] = val["dns_queries"]

            result.append(entry)
        return result

    while _run_loop_flag:
        now = time.time()

        # inotify config reload
        if inotify_fd is not None and (now - last_inotify_check) > 0.5:
            last_inotify_check = now
            try:
                import select
                r, _, _ = select.select([inotify_fd], [], [], 0)
                if r:
                    os.read(inotify_fd, 4096)
                    new_cfg = load_config(_CONFIG_PATH)
                    cfg.clear()
                    cfg.update(new_cfg)
                    _logger.log_event({"event": "config_reloaded"})
            except Exception:
                pass

        targets = cfg.get("targets", [])

        # Fetch events from BPF map
        events = fetch_events(map_id)

        # Deduplicate by timestamp_ns
        events, seen_events = deduplicate_events(events, seen_events)

        # Filter by process comm + event type rules
        events = filter_events(events, targets)

        # Aggregate by process and write to JSONL log
        aggregated = _aggregate_by_process(events)
        for entry in aggregated:
            _logger.log_event(entry)

        time.sleep(poll_interval)

    # ── Shutdown ──────────────────────────────────────────────────────
    _logger.log_event({"event": "daemon_stopping"})
    _logger.close()
    unload_bpf(_PIN_DIR)
    _remove_pid()


# ── CLI entry ──────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m agent_audit <start|stop>", file=sys.stderr)
        sys.exit(1)
    action = sys.argv[1]
    runner = DaemonRunner()
    if action == "start":
        runner.start()
    elif action == "stop":
        runner.stop()
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        sys.exit(1)
