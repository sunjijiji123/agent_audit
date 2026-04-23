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
from pathlib import Path
from typing import List, Dict, Set, Optional

# Path to loader shared library
_LOADER_SO = str(Path(__file__).resolve().parent.parent.parent / "ebpf" / "loader.so")


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

            cls._lib.bpf_dump_events.restype = ctypes.c_char_p
            cls._lib.bpf_dump_events.argtypes = []

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


def load_bpf() -> bool:
    """Load BPF program via libbpf skeleton.

    Returns True on success.
    """
    lib = _BPFLoaderLib.get()
    if not lib:
        return False

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
