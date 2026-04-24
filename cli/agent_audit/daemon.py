"""Daemon runner — loads BPF, polls map, writes JSONL with BPF-packed process chain."""

import fnmatch
import os
import sys
import time
import signal
import json
from collections import defaultdict
from pathlib import Path
from typing import Optional, Set, Dict, Any

from .config import load_config, save_config, _get_config_path
from .bpf_loader import load_bpf, register_pid, update_agent_tree, fetch_events, deduplicate_events, unload_bpf, set_elf_path
from .log_rotator import make_audit_logger, make_runtime_logger


def _get_resource_root() -> Path:
    """Return project root, handling PyInstaller _MEIPASS."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent.parent


_PID_FILE = "/tmp/agent-audit-daemon.pid"
_PIN_DIR = "/sys/fs/bpf/audit"


_CONFIG_PATH = str(_get_config_path())

_run_loop_flag = True
_logger: Optional[object] = None
_runtime_logger: Optional[object] = None


# ── Target scanning ───────────────────────────────────────────────────────────

def _scan_targets(cfg: dict, runtime_logger: Optional[object] = None) -> int:
    """Scan /proc for processes matching targets, register into whitelist.

    Targets are matched by either ``process`` (comm name) or ``processpath``
    (executable path glob), whichever is configured. Returns number of newly
    registered PIDs.
    """
    targets = cfg.get("targets", [])
    if not targets:
        return 0

    # Separate targets by match type
    comm_targets = []
    path_targets = []
    for t in targets:
        if not t.get("enabled", True):
            continue
        if t.get("process"):
            comm_targets.append(t)
        elif t.get("processpath"):
            path_targets.append(t)

    if not comm_targets and not path_targets:
        return 0

    registered = 0
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            matched = False

            # Try comm-based matching
            if comm_targets:
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        comm = f.read().strip()
                except (OSError, FileNotFoundError):
                    comm = None

                if comm:
                    for target in comm_targets:
                        if comm == target["process"]:
                            matched = True
                            break

            # Try path-based matching (only if not already matched)
            if not matched and path_targets:
                try:
                    exe = os.readlink(f"/proc/{pid}/exe")
                except (OSError, FileNotFoundError):
                    exe = None

                if exe:
                    for target in path_targets:
                        if fnmatch.fnmatch(exe, target["processpath"]):
                            matched = True
                            break

            if matched:
                if register_agent_pid(pid, runtime_logger):
                    registered += 1
    except Exception:
        pass

    return registered


# ── PID whitelist management ───────────────────────────────────────────────────────

def register_agent_pid(pid: int, runtime_logger: Optional[object] = None) -> bool:
    """Register Agent root PID into pid_whitelist map.

    Returns True on success. Logs errors if runtime_logger provided.
    """
    # Check PID exists
    if not os.path.exists(f"/proc/{pid}"):
        if runtime_logger:
            runtime_logger.error(f"PID {pid} does not exist")
        return False

    # Read comm from /proc
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            comm = f.read().strip()
    except FileNotFoundError:
        if runtime_logger:
            runtime_logger.error(f"Cannot read /proc/{pid}/comm")
        return False

    # Write to pid_whitelist map via loader
    if not register_pid(pid, root_pid=pid, depth=0):
        if runtime_logger:
            runtime_logger.error(f"Failed to update pid_whitelist for PID {pid}")
        return False

    # Also add to agent_tree so pack_process_chain can find the root
    if not update_agent_tree(pid, comm):
        if runtime_logger:
            runtime_logger.warning(f"Failed to update agent_tree for PID {pid} (chain may be incomplete)")

    if runtime_logger:
        runtime_logger.info(f"Agent PID registered: {pid} (comm={comm})")

    return True


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

    # Initialize dual logger system
    _logger = make_audit_logger(log_path, max_size_mb, backup_count)
    runtime_log_dir = Path(__file__).resolve().parent.parent.parent / "logs"
    runtime_log_path = str(runtime_log_dir / "runtime.log")
    _runtime_logger = make_runtime_logger(runtime_log_path, max_size_mb=10, backup_count=3)

    inotify_fd = _setup_inotify(_CONFIG_PATH)
    last_inotify_check = 0.0

    # ── Resolve BPF ELF path ────────────────────────────────────────
    resource_root = _get_resource_root()
    bpf_elf = cfg.get("daemon", {}).get("bpf_elf", "")

    # If relative path, resolve against resource root (daemon forks and chdirs "/")
    if bpf_elf and not os.path.isabs(bpf_elf):
        resolved = str(resource_root / bpf_elf)
        if os.path.exists(resolved):
            bpf_elf = resolved

    embedded_elf = str(resource_root / "ebpf" / "audit.bpf.o")
    if bpf_elf and os.path.exists(bpf_elf):
        pass  # user-defined path valid
    elif os.path.exists(embedded_elf):
        bpf_elf = embedded_elf
    else:
        print(f"BPF ELF not found: {bpf_elf or embedded_elf}", file=sys.stderr)
        return

    set_elf_path(bpf_elf)

    # ── Load BPF program ──────────────────────────────────────────────
    if load_bpf():
        _runtime_logger.info(f"BPF loaded via libbpf: {bpf_elf}")
    else:
        _runtime_logger.error("BPF load failed")
        _logger.close()
        _runtime_logger.close()
        return

    # Register Agent PIDs from config
    agent_pids = cfg.get("agent_pids", [])
    for pid in agent_pids:
        if not register_agent_pid(pid, _runtime_logger):
            _runtime_logger.error(f"Failed to register Agent PID {pid}")

    _runtime_logger.info(f"Daemon started, agent_pids: {agent_pids}")

    # Initial scan for matching targets
    scan_interval = 5.0
    last_scan_time = 0.0
    n = _scan_targets(cfg, _runtime_logger)
    if n:
        _runtime_logger.info(f"Target scan registered {n} PIDs")

    seen_events: Set[int] = set()

    # ── BPF timestamp conversion ─────────────────────────────────────────────────
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

    # ── /proc 进程信息读取 ─────────────────────────────────────────────
    def _read_proc_info(pid: int) -> Dict:
        """从 /proc 读取进程的 cmdline, exe, cwd, ppid."""
        info = {"cmdline": "", "exe": "", "cwd": "", "ppid": 0}
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                info["cmdline"] = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except (FileNotFoundError, PermissionError):
            pass
        try:
            info["exe"] = os.readlink(f"/proc/{pid}/exe")
        except (OSError, PermissionError):
            pass
        try:
            info["cwd"] = os.readlink(f"/proc/{pid}/cwd")
        except (OSError, PermissionError):
            pass
        try:
            with open(f"/proc/{pid}/stat") as f:
                fields = f.read().split()
                info["ppid"] = int(fields[3])
        except (FileNotFoundError, ValueError, IndexError):
            pass
        return info

    # ── Chain 格式化 ──────────────────────────────────────────────────
    def _format_chain_string(chain_array: list) -> str:
        """将 BPF chain 数组转换为 spec 字符串格式: 'name(pid)->name(pid)->...'."""
        if not chain_array:
            return ""
        parts = []
        for node in chain_array:
            parts.append(f"{node['comm']}({node['pid']})")
        return "->".join(parts)

    # ── fd/bytes 解析 ──────────────────────────────────────────────────
    def _parse_fd_bytes(data: str) -> tuple:
        """解析 'fd=X bytes=Y' 格式, 返回 (fd, bytes)."""
        fd, nbytes = -1, 0
        for part in data.split():
            if part.startswith("fd="):
                try:
                    fd = int(part[3:])
                except ValueError:
                    pass
            elif part.startswith("bytes="):
                try:
                    nbytes = int(part[6:])
                except ValueError:
                    pass
        return fd, nbytes

    # ── fd 路径解析 ─────────────────────────────────────────────────────
    def _resolve_fd_path(pid: int, fd: int) -> str:
        """从 /proc/{pid}/fd/{fd} 解析文件路径."""
        try:
            return os.readlink(f"/proc/{pid}/fd/{fd}")
        except (OSError, PermissionError):
            return ""

    # ── Object 字段格式化 ───────────────────────────────────────────────
    def _format_object(event_type: str, action: str, data: str, pid: int) -> tuple:
        """根据事件类型和 action 格式化 object 字段，返回 (key, dict)."""
        if event_type == "FILE":
            if action in ("read", "write"):
                # data = "fd=X bytes=Y"
                fd, nbytes = _parse_fd_bytes(data)
                path = _resolve_fd_path(pid, fd) if fd >= 0 else ""
                return "file", {"fd": fd, "bytes": nbytes, "path": path}
            else:
                # open 事件, data = 文件路径
                return "file", {"path": data}
        elif event_type == "NET":
            if action in ("send", "recv"):
                # data = "fd=X bytes=Y"
                fd, nbytes = _parse_fd_bytes(data)
                return "network", {"fd": fd, "bytes": nbytes}
            # connect 事件: C loader 输出 "AF_INET ip:port" 或 "AF_INET6 [...]:port"
            if data.startswith("AF_INET6"):
                addr = data[len("AF_INET6 "):]
                return "network", {"dst": addr, "family": "AF_INET6"}
            elif data.startswith("AF_INET"):
                addr = data[len("AF_INET "):]
                return "network", {"dst": addr, "family": "AF_INET"}
            else:
                return "network", {"dst": data, "family": "AF_INET"}
        elif event_type == "DNS":
            return "dns", {"query": data}
        else:
            return "unknown", {"raw": data}

    # ── 单事件日志构建 ─────────────────────────────────────────────────
    def _build_single_event_log(event: Dict) -> Dict:
        """将单个 BPF 事件转换为 JSON-Audit 日志（严格遵循 log-format spec）."""
        ts_ns = event.get("ts_ns", 0)
        ts_iso = _convert_bpf_timestamp(ts_ns)

        pid = event.get("pid", 0)
        comm = event.get("comm", "")

        # chain: 数组 → spec 字符串格式
        chain_str = _format_chain_string(event.get("chain", []))

        # /proc 进程信息
        proc_info = _read_proc_info(pid)

        # 优先使用 BPF 传来的 action 字段，fallback 到 type 推断
        action = event.get("action") or _infer_action_from_type(event.get("type", ""))

        log_entry = {
            "ts": ts_iso,
            "type": event.get("type", "UNKNOWN"),
            "action": action,
            "process": {
                "pid": pid,
                "comm": comm,
                "cmdline": proc_info["cmdline"],
                "exe": proc_info["exe"],
                "cwd": proc_info["cwd"],
                "ppid": proc_info["ppid"],
                "chain": chain_str,
            }
        }

        object_key, object_value = _format_object(event.get("type"), action, event.get("data", ""), pid)
        log_entry[object_key] = object_value

        return log_entry

    while _run_loop_flag:
        now = time.time()

        # Periodic target scan
        if (now - last_scan_time) > scan_interval:
            last_scan_time = now
            n = _scan_targets(cfg, _runtime_logger)
            if n:
                _runtime_logger.info(f"Target scan registered {n} new PIDs")

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
                    n = _scan_targets(cfg, _runtime_logger)
                    if n:
                        _runtime_logger.info(f"Config reload scan registered {n} new PIDs")
            except Exception:
                pass

        # Fetch events from BPF map
        events = fetch_events()

        # Deduplicate by timestamp_ns
        events, seen_events = deduplicate_events(events, seen_events)

        # Process each event individually and write to JSONL log
        for event in events:
            log_entry = _build_single_event_log(event)

            # Filter out noisy read/write events with meaningless paths
            if event.get("type") == "FILE" and event.get("action") in ("read", "write"):
                path = log_entry.get("file", {}).get("path", "")
                if not path or path.startswith("/dev/pts/") or path.startswith("socket:") or path.startswith("pipe:"):
                    continue

            _logger.log_event(log_entry)

        time.sleep(poll_interval)

    # ── Shutdown ──────────────────────────────────────────────────────
    _runtime_logger.info("Daemon stopping")
    _logger.close()
    _runtime_logger.close()
    unload_bpf()
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
