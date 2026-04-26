"""BPF loader via libbpf skeleton + ctypes.

Replaces bpftool subprocess with direct C library calls.

Provides:
    load_bpf()              — load BPF program via libbpf skeleton
    register_pid(pid)     — add PID to whitelist
    fetch_events()         — fetch events as JSON list
    unload_bpf()           — unload BPF program
"""

import ctypes
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Set, Optional, TypedDict


class TreeNode(ctypes.Structure):
    """Mirrors struct tree_node from loader.c."""
    _fields_ = [
        ("parent_pid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("fork_time", ctypes.c_ulonglong),
    ]


def _get_project_root() -> Path:
    """Return project root, handling PyInstaller _MEIPASS."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent.parent


# Path to loader shared library
_LOADER_SO = str(_get_project_root() / "ebpf" / "loader.so")


class _BPFLoaderLib:
    """Lazy-loaded ctypes wrapper for loader.so functions."""

    _lib = None
    _initialized = False

    @classmethod
    def _load(cls):
        if cls._initialized:
            return cls._lib is not None

        if not os.path.exists(_LOADER_SO):
            cls._initialized = True
            return False

        try:
            cls._lib = ctypes.CDLL(_LOADER_SO)

            # Setup function signatures
            cls._lib.bpf_load.restype = ctypes.c_int
            cls._lib.bpf_load.argtypes = []

            cls._lib.bpf_unload.restype = None
            cls._lib.bpf_unload.argtypes = []

            cls._lib.bpf_map_update_pid_whitelist.restype = ctypes.c_int
            cls._lib.bpf_map_update_pid_whitelist.argtypes = [
                ctypes.c_uint,  # pid
                ctypes.c_uint,  # root_pid
                ctypes.c_ubyte,  # depth
            ]

            cls._lib.bpf_map_delete_pid_whitelist.restype = ctypes.c_int
            cls._lib.bpf_map_delete_pid_whitelist.argtypes = [ctypes.c_uint]

            cls._lib.bpf_map_update_agent_tree.restype = ctypes.c_int
            cls._lib.bpf_map_update_agent_tree.argtypes = [
                ctypes.c_uint,      # pid
                ctypes.c_char_p,    # comm
            ]

            cls._lib.bpf_dump_events.restype = ctypes.c_char_p
            cls._lib.bpf_dump_events.argtypes = []

            cls._lib.bpf_set_elf_path.restype = None
            cls._lib.bpf_set_elf_path.argtypes = [ctypes.c_char_p]

            cls._lib.bpf_map_lookup_agent_tree.restype = ctypes.c_int
            cls._lib.bpf_map_lookup_agent_tree.argtypes = [
                ctypes.c_uint,
                ctypes.POINTER(TreeNode),
            ]

            cls._initialized = True
            return True
        except Exception:
            cls._initialized = True
            return False

    @classmethod
    def get(cls):
        if not cls._initialized:
            cls._load()
        return cls._lib


# ── Public API ────────────────────────────────────────────────────────────────


def loader_available() -> bool:
    """Return True if loader.so is available and loaded successfully."""
    return _BPFLoaderLib.get() is not None


def set_elf_path(path: str) -> bool:
    """Set the BPF ELF object path before loading."""
    lib = _BPFLoaderLib.get()
    if not lib:
        return False
    try:
        lib.bpf_set_elf_path(path.encode("utf-8"))
        return True
    except Exception:
        return False


def load_bpf(elf_path: Optional[str] = None) -> bool:
    """Load BPF program via libbpf skeleton.

    Args:
        elf_path: Optional path to BPF ELF object. If provided, calls
                  set_elf_path() before loading.

    Returns True on success.
    """
    lib = _BPFLoaderLib.get()
    if not lib:
        return False

    if elf_path:
        set_elf_path(elf_path)

    try:
        return lib.bpf_load() == 0
    except Exception:
        return False


def unload_bpf() -> bool:
    """Unload BPF program."""
    lib = _BPFLoaderLib.get()
    if not lib:
        return False

    try:
        lib.bpf_unload()
        return True
    except Exception:
        return False


def register_pid(pid: int, root_pid: Optional[int] = None, depth: int = 0) -> bool:
    """Add a PID to the whitelist map.

    Args:
        pid: The PID to whitelist
        root_pid: The root agent PID (defaults to pid itself)
        depth: Process tree depth (0=root)

    Returns True on success.
    """
    if root_pid is None:
        root_pid = pid

    lib = _BPFLoaderLib.get()
    if not lib:
        return False

    try:
        return lib.bpf_map_update_pid_whitelist(
            ctypes.c_uint(pid),
            ctypes.c_uint(root_pid),
            ctypes.c_ubyte(depth),
        ) == 0
    except Exception:
        return False


def unregister_pid(pid: int) -> bool:
    """Remove a PID from the whitelist map.

    Returns True on success.
    """
    lib = _BPFLoaderLib.get()
    if not lib:
        return False

    try:
        return lib.bpf_map_delete_pid_whitelist(ctypes.c_uint(pid)) == 0
    except Exception:
        return False


def update_agent_tree(pid: int, comm: str) -> bool:
    """Add a PID to agent_tree map (for root process chain tracking).

    Args:
        pid: The PID to add
        comm: Process name (max 16 chars)

    Returns True on success.
    """
    lib = _BPFLoaderLib.get()
    if not lib:
        return False

    try:
        return lib.bpf_map_update_agent_tree(
            ctypes.c_uint(pid),
            comm.encode("utf-8"),
        ) == 0
    except Exception:
        return False


def lookup_agent_tree(pid: int) -> Optional[Dict]:
    """Look up a PID in the agent_tree BPF map.

    Returns dict with parent_pid, comm, fork_time; or None if not found.
    """
    lib = _BPFLoaderLib.get()
    if not lib:
        return None

    node = TreeNode()
    try:
        if lib.bpf_map_lookup_agent_tree(ctypes.c_uint(pid), ctypes.byref(node)) != 0:
            return None
    except Exception:
        return None

    return {
        "parent_pid": node.parent_pid,
        "comm": node.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "fork_time": node.fork_time,
    }


def fetch_events() -> List[Dict]:
    """Fetch events from BPF map, return parsed event dicts.

    Events are automatically cleared from map after fetch.
    """
    lib = _BPFLoaderLib.get()
    if not lib:
        return []

    try:
        json_str = lib.bpf_dump_events()
        if not json_str:
            return []

        events = json.loads(json_str.decode("utf-8"))
        return events if isinstance(events, list) else []
    except Exception:
        return []


def deduplicate_events(
    new_events: List[Dict], seen_keys: Set[int]
) -> tuple:
    """Filter out events already seen (by key=ts_ns). Returns (unique_events, updated_keys)."""
    unique = [e for e in new_events if e.get("ts_ns") not in seen_keys]
    for e in unique:
        seen_keys.add(e.get("ts_ns", 0))
    return unique, seen_keys


def get_map_id() -> int:
    """Legacy function for backward compatibility. Always returns 1 since map_id not needed for CO-RE loader."""
    return 1
