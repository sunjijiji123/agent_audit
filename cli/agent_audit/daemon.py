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
from .log_rotator import make_audit_logger, make_runtime_logger

_PID_FILE = "/root/tmp/agent-audit-daemon.pid"
_CONFIG_PATH = str(Path(__file__).resolve().parent.parent.parent / "config.json")
_PIN_DIR = "/sys/fs/bpf/audit"

_run_loop_flag = True
_logger: Optional[object] = None
_runtime_logger: Optional[object] = None


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
    global _run_loop_flag, _logger, _runtime_logger

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

    # Initialize dual logger system
    _logger = make_audit_logger(log_path, max_size_mb, backup_count)
    runtime_log_dir = Path(__file__).resolve().parent.parent.parent / "logs"
    runtime_log_path = str(runtime_log_dir / "runtime.log")
    _runtime_logger = make_runtime_logger(runtime_log_path, max_size_mb=10, backup_count=3)

    inotify_fd = _setup_inotify(_CONFIG_PATH)
    last_inotify_check = 0.0

    # ── Load BPF program ──────────────────────────────────────────────
    targets = cfg.get("targets", [])
    process_names = [t["process"] for t in targets if t.get("enabled", True)]

    if load_bpf(bpf_elf, _PIN_DIR):
        _runtime_logger.info(f"BPF loaded: {bpf_elf}, targets: {process_names}")
    else:
        _runtime_logger.error(f"BPF load failed: {bpf_elf}")
        _logger.close()
        _runtime_logger.close()
        return

    map_id = get_map_id()
    if map_id < 0:
        _runtime_logger.error("BPF map ID not found")
        _logger.close()
        _runtime_logger.close()
        return

    # Save map_id to config for reference
    cfg.setdefault("daemon", {})["bpf_map_id"] = map_id
    save_config(cfg, _CONFIG_PATH)

    # Clear existing entries so we start fresh
    clear_map(map_id)

    _runtime_logger.info(f"Daemon started, map_id: {map_id}")

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

    # ── 进程信息缓存 ───────────────────────────────────────────────────
    _process_info_cache: Dict[int, Dict] = {}
    _cache_timestamps: Dict[int, float] = {}
    _CACHE_TTL = 5.0  # 5秒缓存有效期

    def _get_process_info_cached(pid: int) -> Dict[str, Any]:
        """带缓存的进程信息获取，减少重复 /proc 读取."""
        now = time.time()
        if pid in _process_info_cache:
            cache_time = _cache_timestamps.get(pid, 0)
            if now - cache_time < _CACHE_TTL:
                return _process_info_cache[pid]
        info = _get_process_info(pid)
        _process_info_cache[pid] = info
        _cache_timestamps[pid] = now
        return info

    # ── 进程链构建 ─────────────────────────────────────────────────────
    def _build_proc_chain(pid: int, max_depth: int = 10, comm: str = "") -> str:
        """构建进程链: 'python3(56105)->bash(1000)->systemd(1)'"""
        chain_parts = []
        current_pid = pid
        visited = set()
        first = True

        for _ in range(max_depth):
            if current_pid <= 0 or current_pid in visited:
                break
            visited.add(current_pid)

            # 获取进程名（首次尝试使用 BPF 事件中的 comm）
            if first and comm:
                name = comm
                first = False
            else:
                try:
                    with open(f"/proc/{current_pid}/comm", "r") as f:
                        name = f.read().strip()
                except FileNotFoundError:
                    name = "unknown"

            chain_parts.append(f"{name}({current_pid})")

            # 获取父进程PID
            try:
                with open(f"/proc/{current_pid}/stat", "r") as f:
                    stat_fields = f.read().split()
                    ppid = int(stat_fields[3]) if len(stat_fields) > 3 else 0
            except FileNotFoundError:
                ppid = 0

            # 到达 systemd 或 kernel
            if ppid <= 1:
                if ppid == 1:
                    try:
                        with open("/proc/1/comm", "r") as f:
                            systemd_name = f.read().strip()
                        chain_parts.append(f"{systemd_name}(1)")
                    except:
                        chain_parts.append("systemd(1)")
                break

            current_pid = ppid

        return "->".join(chain_parts)

    # ── BPF 时间戳转换 ─────────────────────────────────────────────────
    _boot_to_epoch_ns = 0
    _last_boot_update = 0.0

    def _get_boot_to_epoch_offset() -> int:
        """计算 CLOCK_BOOTTIME → wall clock 的偏移量."""
        nonlocal _boot_to_epoch_ns, _last_boot_update

        now = time.time()
        # 每分钟更新一次偏移量
        if now - _last_boot_update > 60.0:
            wall_ns = time.time_ns()

            # 获取 boot time (使用 clock_gettime)
            import ctypes
            libc = ctypes.CDLL('libc.so.6', use_errno=True)

            class Timespec(ctypes.Structure):
                _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]

            ts = Timespec()
            # CLOCK_BOOTTIME = 7
            libc.clock_gettime(7, ctypes.byref(ts))
            boot_ns = ts.tv_sec * 1_000_000_000 + ts.tv_nsec

            _boot_to_epoch_ns = wall_ns - boot_ns
            _last_boot_update = now

        return _boot_to_epoch_ns

    def _convert_bpf_timestamp(ts_ns: int) -> str:
        """将 BPF boot time 转换为 ISO8601 字符串."""
        from datetime import datetime
        offset = _get_boot_to_epoch_offset()
        epoch_ns = ts_ns + offset
        seconds = epoch_ns / 1_000_000_000
        dt = datetime.fromtimestamp(seconds)
        return dt.isoformat()

    # ── Action 推断 ─────────────────────────────────────────────────────
    def _infer_action_from_type(event_type: str) -> str:
        """从事件类型推断 action (Phase 1 简单映射)."""
        action_map = {
            "FILE": "open",
            "NET": "connect",
            "DNS": "resolve"
        }
        return action_map.get(event_type, "unknown")

    # ── Object 字段格式化 ───────────────────────────────────────────────
    def _format_object(event_type: str, data: str) -> tuple:
        """根据事件类型格式化 object 字段，返回 (key, dict)."""
        if event_type == "FILE":
            return "file", {"path": data}
        elif event_type == "NET":
            if ":" in data and not data.startswith("family"):
                return "network", {"dst": data, "family": "AF_INET"}
            else:
                return "network", {"dst": data, "family": data}
        elif event_type == "DNS":
            return "dns", {"query": data}
        else:
            return "unknown", {"raw": data}

    # ── 单事件日志构建 ─────────────────────────────────────────────────
    def _build_single_event_log(event: Dict) -> Dict:
        """将单个 BPF 事件转换为 JSON-Audit 日志."""
        # 时间戳转换
        ts_ns = event.get("ts_ns", 0)
        ts_iso = _convert_bpf_timestamp(ts_ns)

        # 获取进程信息
        pid = event.get("pid", 0)
        proc_info = _get_process_info_cached(pid)

        # 构建进程链
        chain = _build_proc_chain(pid, comm=event.get("comm", ""))

        # 确定 action
        action = _infer_action_from_type(event.get("type", ""))

        # 组装日志
        log_entry = {
            "ts": ts_iso,
            "type": event.get("type", "UNKNOWN"),
            "action": action,
            "process": {
                "pid": pid,
                "comm": event.get("comm", ""),
                "cmdline": proc_info.get("cmdline", ""),
                "exe": proc_info.get("exe", ""),
                "cwd": proc_info.get("cwd", ""),
                "ppid": proc_info.get("ppid", 0),
                "chain": chain
            }
        }

        # 动态 object 字段
        object_key, object_value = _format_object(event.get("type"), event.get("data"))
        log_entry[object_key] = object_value

        return log_entry

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
                    _runtime_logger.info("Config reloaded")
            except Exception:
                pass

        targets = cfg.get("targets", [])

        # Fetch events from BPF map
        events = fetch_events(map_id)

        # Deduplicate by timestamp_ns
        events, seen_events = deduplicate_events(events, seen_events)

        # Filter by process comm + event type rules
        events = filter_events(events, targets)

        # Process each event individually and write to JSONL log
        for event in events:
            log_entry = _build_single_event_log(event)
            _logger.log_event(log_entry)

        time.sleep(poll_interval)

    # ── Shutdown ──────────────────────────────────────────────────────
    _runtime_logger.info("Daemon stopping")
    _logger.close()
    _runtime_logger.close()
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
