"""Daemon runner — loads BPF, polls map, writes JSONL with BPF-packed process chain."""

import fnmatch
import hashlib
import os
import sys
import time
import signal
import json
import uuid
import functools
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set, Dict, Any, Tuple

from .config import load_config, save_config, _get_config_path
from .bpf_loader import load_bpf, register_pid, update_agent_tree, fetch_events, deduplicate_events, unload_bpf, set_elf_path, lookup_agent_tree
from .log_rotator import make_audit_logger, make_runtime_logger

# DAS-DS constants
AGENT_AUDIT_NS = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

_EVENT_TYPE_MAP = {
    "FILE": ("fileEvent", 120003),
    "NET": ("networkConnect", 130001),
    "DNS": ("dnsQuery", 130003),
    "FORK": ("processCreate", 110001),
}

PROC_CACHE_TTL = 30
PRECACHE_TTL = 5.0


@dataclass
class ProcInfo:
    cmdline: str = ""
    exe: str = ""
    cwd: str = ""
    ppid: int = 0
    username: str = ""
    cached_at: float = 0.0


# Pre-cache for short-lived processes, populated on FORK events
_proc_precache: Dict[int, Tuple[float, ProcInfo]] = {}


def _precache_proc_info(pid: int) -> bool:
    """Try to read /proc metadata for pid and store in pre-cache.

    Returns True on success (at least one field populated), False on failure.
    Never raises exceptions.
    """
    info = ProcInfo(cached_at=time.time())
    any_field = False
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            info.cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            any_field = True
    except (OSError, PermissionError):
        pass
    try:
        info.exe = os.readlink(f"/proc/{pid}/exe")
        any_field = True
    except (OSError, PermissionError):
        pass
    try:
        info.cwd = os.readlink(f"/proc/{pid}/cwd")
        any_field = True
    except (OSError, PermissionError):
        pass
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    import pwd
                    info.username = pwd.getpwuid(uid).pw_name
                    any_field = True
                    break
    except (OSError, PermissionError, ValueError, IndexError, KeyError):
        pass
    if any_field:
        _proc_precache[pid] = (info.cached_at, info)
    return any_field


def _get_precached_proc_info(pid: int) -> Optional[Dict]:
    """Return pre-cached proc info if available and not expired, else None."""
    entry = _proc_precache.get(pid)
    if entry is None:
        return None
    ts, info = entry
    if time.time() - ts > PRECACHE_TTL:
        _proc_precache.pop(pid, None)
        return None
    return {"cmdline": info.cmdline, "exe": info.exe,
            "cwd": info.cwd, "ppid": info.ppid,
            "username": info.username}


def _force_cleanup_audit_bpf() -> None:
    """Force-detach any stale audit BPF programs from previous daemon runs.

    When a daemon is killed (SIGKILL) or crashes, BPF programs may remain
    loaded in kernel memory. This function finds and closes their link fds
    by iterating /proc/self/fd and checking for BPF links.
    """
    import struct
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)

        for fd_name in os.listdir("/proc/self/fd"):
            try:
                fd = int(fd_name)
            except ValueError:
                continue
            try:
                link = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                continue
            # BPF links appear as anon_inode:[bpf-link]
            if "bpf-link" in link:
                # Check if this link is for an audit tracepoint
                # by reading link info (we just close stale ones)
                os.close(fd)
        # Also close any open BPF map FDs from old objects
    except (OSError, PermissionError, ValueError):
        pass


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
    poll_interval_min = cfg.get("daemon", {}).get("poll_interval_min_sec", 0.05)
    poll_interval_max = cfg.get("daemon", {}).get("poll_interval_max_sec", 2.0)

    # Adaptive polling state
    current_interval = poll_interval_min
    empty_count = 0

    # Polling stats
    last_stats_time = 0.0
    stats_interval = 60.0
    total_with_events = 0
    total_without_events = 0
    total_resets = 0

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

    # ── Clean up any stale BPF state from previous runs ──────────────
    # Previous daemon may have crashed without cleanup, leaving orphaned
    # BPF programs loaded. Force-cleanup before loading new ones.
    unload_bpf()
    import shutil
    shutil.rmtree(_PIN_DIR, ignore_errors=True)
    _force_cleanup_audit_bpf()

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

    # ── DAS-DS helpers ───────────────────────────────────────────────────────
    def _generate_process_guid(root_pid: int, fork_time_ns: int) -> str:
        return str(uuid.uuid5(AGENT_AUDIT_NS, f"{root_pid}:{fork_time_ns}"))

    def _generate_logfuz_id(event_type: str, process_id: int, unix_time: int,
                            op_type: str, data_key: str) -> str:
        raw = f"{event_type}{process_id}{unix_time}{op_type}{data_key}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    @functools.lru_cache(maxsize=512)
    def _compute_md5(path: str) -> str:
        try:
            h = hashlib.md5()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return ""

    @functools.lru_cache(maxsize=512)
    def _detect_elf_file(path: str) -> str:
        """Detect ELF executable files using magic byte check."""
        try:
            with open(path, "rb") as f:
                return "ELF" if f.read(4) == b'\x7fELF' else ""
        except (OSError, PermissionError):
            return ""

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

    def _convert_bpf_timestamp(ts_ns: int) -> tuple:
        """将 BPF boot time 转换为 (localTime 字符串, unixTime epoch秒)."""
        offset = _get_boot_to_epoch_offset()
        epoch_ns = ts_ns + offset
        epoch_s = epoch_ns // 1_000_000_000
        dt = datetime.fromtimestamp(epoch_s, tz=timezone.utc).astimezone()
        # 自定义格式：YYYY-MM-DD HH:MM:SS（无时区后缀）
        local_time = dt.strftime("%Y-%m-%d %H:%M:%S")
        return local_time, epoch_s

    # ── Action 推断 ─────────────────────────────────────────────────────
    def _infer_action_from_type(event_type: str) -> str:
        """从事件类型推断 action (Phase 1 简单映射)."""
        action_map = {
            "FILE": "open",
            "NET": "connect",
            "DNS": "resolve"
        }
        return action_map.get(event_type, "unknown")

    # ── /proc 进程信息读取（带缓存） ─────────────────────────────────────
    _proc_cache: Dict[int, ProcInfo] = {}

    def _get_proc_info(pid: int) -> Dict:
        """从缓存获取进程信息，未命中或过期则读 /proc 并更新缓存。"""
        # 1. Check pre-cache (highest priority, fast path)
        precached = _get_precached_proc_info(pid)
        if precached is not None:
            return precached

        now = time.time()
        cached = _proc_cache.get(pid)
        if cached and (now - cached.cached_at) < PROC_CACHE_TTL:
            return {"cmdline": cached.cmdline, "exe": cached.exe,
                    "cwd": cached.cwd, "ppid": cached.ppid,
                    "username": cached.username}

        # ppid: prefer agent_tree, fallback to /proc/stat
        ppid = 0
        tree_entry = lookup_agent_tree(pid)
        if tree_entry:
            ppid = tree_entry["parent_pid"]

        info = ProcInfo(cached_at=now)
        # Each field independent: single failure doesn't block others
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                info.cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except (OSError, PermissionError):
            pass
        try:
            info.exe = os.readlink(f"/proc/{pid}/exe")
        except (OSError, PermissionError):
            pass
        try:
            info.cwd = os.readlink(f"/proc/{pid}/cwd")
        except (OSError, PermissionError):
            pass

        # ppid fallback to /proc/stat if agent_tree lookup failed
        if ppid == 0:
            try:
                with open(f"/proc/{pid}/stat") as f:
                    fields = f.read().split()
                    ppid = int(fields[3])
            except (FileNotFoundError, ValueError, IndexError):
                pass
        info.ppid = ppid

        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        import pwd
                        info.username = pwd.getpwuid(uid).pw_name
                        break
        except (FileNotFoundError, ValueError, IndexError, OSError, KeyError):
            pass

        _proc_cache[pid] = info
        return {"cmdline": info.cmdline, "exe": info.exe,
                "cwd": info.cwd, "ppid": info.ppid,
                "username": info.username}

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

    # ── NET dest/src helpers ──────────────────────────────────────────
    def _parse_net_dest(data: str) -> tuple:
        """Parse sockaddr string from loader.c into (family, dest_ip, dest_port)."""
        if data.startswith("AF_INET6 "):
            rest = data[len("AF_INET6 "):]
            bracket_end = rest.rfind(']')
            if bracket_end > 0 and rest.startswith('['):
                dest_ip = rest[1:bracket_end]
                port_str = rest[bracket_end + 1:]
                if port_str.startswith(':'):
                    try:
                        return "AF_INET6", dest_ip, int(port_str[1:])
                    except ValueError:
                        pass
            return "AF_INET6", rest, 0
        elif data.startswith("AF_INET "):
            rest = data[len("AF_INET "):]
            colon = rest.rfind(':')
            if colon > 0:
                try:
                    return "AF_INET", rest[:colon], int(rest[colon + 1:])
                except ValueError:
                    pass
            return "AF_INET", rest, 0
        else:
            return "unknown", "", 0

    def _lookup_net_src(pid: int, dest_ip: str, dest_port: int) -> tuple:
        """Look up source address from /proc/{pid}/net/tcp by matching dest."""
        if dest_port == 0 or not dest_ip:
            return "0.0.0.0", 0
        try:
            parts = dest_ip.split('.')
            if len(parts) != 4:
                return "0.0.0.0", 0
            hex_ip = f"{int(parts[3]):02X}{int(parts[2]):02X}{int(parts[1]):02X}{int(parts[0]):02X}"
        except (ValueError, IndexError):
            return "0.0.0.0", 0

        remote_pattern = f"{hex_ip}:{dest_port:04X}"

        try:
            with open(f"/proc/{pid}/net/tcp") as f:
                for line in f:
                    fields = line.split()
                    if len(fields) < 4 or fields[0].endswith(':'):
                        continue
                    if fields[2] == remote_pattern:
                        local_parts = fields[1].split(':')
                        if len(local_parts) == 2:
                            src_hex_ip = local_parts[0]
                            ip_parts = [str(int(src_hex_ip[i:i + 2], 16)) for i in range(6, -1, -2)]
                            return '.'.join(ip_parts), int(local_parts[1], 16)
        except (OSError, PermissionError, ValueError):
            pass

        return "0.0.0.0", 0

    # ── 单事件日志构建（DAS-DS 扁平格式） ───────────────────────────────
    def _build_single_event_log(event: Dict) -> Dict:
        """将单个 BPF 事件转换为 DAS-DS 扁平 JSON 日志."""
        bpf_type = event.get("type", "UNKNOWN")
        action = event.get("action") or _infer_action_from_type(bpf_type)
        pid = event.get("pid", 0)
        comm = event.get("comm", "")
        data = event.get("data", "")
        chain = event.get("chain", [])

        # Timestamps
        ts_ns = event.get("ts_ns", 0)
        local_time, unix_time = _convert_bpf_timestamp(ts_ns)

        # eventType / rawLogNum mapping
        event_type, raw_log_num = _EVENT_TYPE_MAP.get(bpf_type, ("unknown", 0))

        # opType (FORK → "create" per DAS-DS spec)
        if action == "fork":
            op_type = "create"
        elif bpf_type == "DNS":
            # DNS events use "connect" per DAS-DS spec (not "resolve")
            op_type = "connect"
        else:
            op_type = action

        # Process info from /proc (cached)
        proc_info = _get_proc_info(pid)

        # root_pid from chain (last element is root), fallback to pid
        root_pid = chain[-1]["pid"] if chain else pid

        # fork_time from agent_tree for stable GUID
        tree_entry = lookup_agent_tree(pid)
        fork_time_ns = tree_entry["fork_time"] if tree_entry else 0

        process_guid = ""

        # parentProcessName: chain[1] is direct parent
        parent_process_name = chain[1]["comm"] if len(chain) >= 2 else ""

        # parent_pid: prefer agent_tree for fork events, then chain, then /proc
        if bpf_type == "FORK":
            # For fork events, parent_pid from agent_tree (BPF filled it)
            parent_pid = tree_entry["parent_pid"] if tree_entry else 0
        else:
            parent_pid = proc_info["ppid"]

        parent_process_guid = ""

        # processMd5: set to empty (calculation deferred)
        process_md5 = ""

        # data_key for logfuzId (deferred - set to empty)
        data_key = ""
        if bpf_type == "FILE":
            if action in ("read", "write"):
                fd, _ = _parse_fd_bytes(data)
                data_key = _resolve_fd_path(pid, fd) if fd >= 0 else ""
            else:
                data_key = data
        elif bpf_type == "NET":
            _, _dest_ip, _dest_port = _parse_net_dest(data)
            data_key = f"{_dest_ip}:{_dest_port}"
        elif bpf_type == "DNS":
            data_key = data
        elif bpf_type == "FORK":
            data_key = str(parent_pid)

        # logfuzId: set to empty (generation deferred)
        logfuz_id = ""

        # Build flat DAS-DS output
        # logType mapping per DAS-DS spec
        log_type_map = {
            "processCreate": "process",
            "fileEvent": "file",
            "networkConnect": "network",
            "dnsQuery": "domain",
        }

        log_entry = {
            "eventType": event_type,
            "rawLogNum": raw_log_num,
            "logType": log_type_map.get(event_type, "agent-audit"),
            "opType": op_type,
            "localTime": local_time,
            "unixTime": unix_time,
            "logfuzId": logfuz_id,
            "processId": str(pid),  # DAS-DS requires string format
            "image": proc_info["exe"],
            "commandLine": proc_info["cmdline"],
            "processUserName": proc_info["username"],
            "processMd5": process_md5,
            "processName": comm,
            "parentProcessName": parent_process_name,
            "processGuid": process_guid,
            "traceId": "",
            "parentProcessGuid": parent_process_guid,
            "parentProcessId": str(parent_pid),  # DAS-DS requires string format
        }

        # Event-specific top-level fields
        if bpf_type == "FILE":
            if action in ("read", "write"):
                # read/write: resolve fd to path, filter directories
                fd, _ = _parse_fd_bytes(data)
                path = _resolve_fd_path(pid, fd) if fd >= 0 else ""
                # Filter directories and symlinks (no metadata)
                if path and os.path.isfile(path):
                    log_entry["filePath"] = path
                else:
                    log_entry["filePath"] = ""
            else:  # open event
                # open: filter directories, collect metadata
                path = data
                # Add empty fields first (deferred capabilities)
                log_entry["fileMd5"] = ""
                log_entry["createTime"] = ""
                log_entry["targetFilename"] = ""

                # Filter directories and symlinks using os.path.isfile
                if path and os.path.isfile(path):
                    log_entry["filePath"] = path
                    # Collect file metadata for regular files
                    try:
                        st = os.stat(path)
                        log_entry["fileSize"] = st.st_size
                        modify_time_dt = datetime.fromtimestamp(st.st_mtime)
                        log_entry["modifyTime"] = modify_time_dt.strftime("%Y-%m-%d %H:%M:%S")
                        log_entry["fileType"] = _detect_elf_file(path)
                    except (OSError, PermissionError):
                        # File deleted or permission denied - fields remain empty
                        log_entry["fileSize"] = 0
                        log_entry["modifyTime"] = ""
                        log_entry["fileType"] = ""
                else:
                    # Directory or symlink - no metadata
                    log_entry["filePath"] = ""
                    log_entry["fileSize"] = 0
                    log_entry["modifyTime"] = ""
                    log_entry["fileType"] = ""
        elif bpf_type == "NET":
            family, dest_ip, dest_port = _parse_net_dest(data)
            if family == "AF_INET":
                src_ip, src_port = _lookup_net_src(pid, dest_ip, dest_port)
            else:
                src_ip, src_port = "0.0.0.0", 0
            log_entry["transProtocol"] = "TCP"
            log_entry["srcAddress"] = src_ip
            log_entry["srcPort"] = src_port
            log_entry["destAddress"] = dest_ip
            log_entry["destPort"] = dest_port
        elif bpf_type == "DNS":
            log_entry["requestDomain"] = data
        elif bpf_type == "FORK":
            if fork_time_ns:
                process_start_time, _ = _convert_bpf_timestamp(fork_time_ns)
                log_entry["processStartTime"] = process_start_time
            else:
                log_entry["processStartTime"] = ""

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

        # ── FORK event pre-cache (tasks 2.1-2.3) ──────────────────────────
        # Only precache child PIDs from FORK events — these are newly created
        # processes that may exit before the next poll. Parent PIDs are typically
        # longer-lived and handled by the normal _get_proc_info cache.
        # Cap at 60 per batch to avoid /proc I/O blocking the event loop.
        precache_pids: Set[int] = set()
        precache_budget = 100
        for event in events:
            if event.get("type") != "FORK":
                continue
            pid = event.get("pid", 0)
            if pid and pid not in precache_pids:
                if precache_budget <= 0:
                    break
                _precache_proc_info(pid)
                precache_pids.add(pid)
                precache_budget -= 1

        # Process each event individually and write to JSONL log
        for event in events:
            log_entry = _build_single_event_log(event)

            # Filter out noisy read/write events with meaningless paths
            if event.get("type") == "FILE" and event.get("action") in ("read", "write"):
                path = log_entry.get("filePath", "")
                if not path or path.startswith("/dev/pts/") or path.startswith("socket:") or path.startswith("pipe:"):
                    continue

            _logger.log_event(log_entry)

        # ── Adaptive polling (tasks 4.4-4.5) ──────────────────────────────
        if events:
            if current_interval > poll_interval_min:
                total_resets += 1
            current_interval = poll_interval_min
            empty_count = 0
            total_with_events += 1
        else:
            empty_count += 1
            current_interval = min(poll_interval_min * (2 ** empty_count), poll_interval_max)
            total_without_events += 1

        # ── Precache cleanup (tasks 5.1) ───────────────────────────────────
        expire_cutoff = time.time() - PRECACHE_TTL
        stale = [p for p, (ts, _) in _proc_precache.items() if ts < expire_cutoff]
        for p in stale:
            _proc_precache.pop(p, None)

        # ── Polling stats logging (task 6.3) ──────────────────────────────
        if now - last_stats_time > stats_interval:
            last_stats_time = now
            _runtime_logger.info(
                f"Polling stats: interval={current_interval:.2f}s, "
                f"with_events={total_with_events}, without_events={total_without_events}, "
                f"resets={total_resets}"
            )

        time.sleep(current_interval)

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
