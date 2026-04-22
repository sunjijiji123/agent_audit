"""BPF map reader via bpftool / fast C reader.

Provides:
    load_bpf(elf_path, pin_dir)  — load BPF ELF via bpftool loadall --autoattach
    get_map_id()                  — find our events map ID via bpftool -j map show
    fetch_events(map_id)          — fetch events (uses bpf_map_dump C binary if available)
    deduplicate_events()          — dedupe by timestamp_ns key
"""

import json
import os
import subprocess
from typing import List, Dict, Set, Optional
from pathlib import Path

# Path to fast C map reader (compiled from bpf_map_dump.c)
_BPF_MAP_DUMP = str(Path(__file__).resolve().parent.parent.parent / "ebpf" / "bpf_map_dump")


# ── BPF loading ────────────────────────────────────────────────────────────────

def load_bpf(elf_path: str, pin_dir: str) -> bool:
    """Load BPF ELF via bpftool prog loadall --autoattach.

    Returns True on success. The pin_dir is where BPF maps/progs are pinned.
    """
    try:
        subprocess.run(
            ["rm", "-rf", pin_dir],
            capture_output=True, text=True, timeout=5,
        )
        subprocess.run(
            ["mkdir", "-p", pin_dir],
            capture_output=True, text=True, timeout=5,
        )
        r = subprocess.run(
            ["bpftool", "prog", "loadall", elf_path, f"{pin_dir}/audit", "autoattach"],
            capture_output=True, text=True, timeout=30,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def unload_bpf(pin_dir: str) -> bool:
    """Remove pinned BPF programs/maps from pin_dir."""
    try:
        subprocess.run(
            ["rm", "-rf", pin_dir],
            capture_output=True, text=True, timeout=5,
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ── map ID discovery ───────────────────────────────────────────────────────────

def get_map_id(before_ids: Optional[List[int]] = None) -> int:
    """Find the events map ID.

    If before_ids provided: diff against current maps (for new-map detection).
    Otherwise: return highest-ID events map from current list (for recovery).
    """
    r = subprocess.run(
        ["python3", "-c",
         "import subprocess,json;"
         "d=json.loads(subprocess.run(['bpftool','-j','map','show'],"
         "capture_output=True,text=True).stdout);"
         "print(','.join(str(m['id']) for m in d if'events' in m.get('name','')))"],
        capture_output=True, text=True, timeout=10,
    )
    all_ids = sorted(int(x) for x in r.stdout.strip().split(",") if x)

    if before_ids is not None:
        existing = set(before_ids)
        diff = [i for i in all_ids if i not in existing]
        return diff[-1] if diff else -1

    # Fallback: return highest-ID events map (for already-loaded BPF)
    return all_ids[-1] if all_ids else -1


def get_whitelist_map_id() -> int:
    """Find the comm_whitelist map ID."""
    r = subprocess.run(
        ["python3", "-c",
         "import subprocess,json;"
         "d=json.loads(subprocess.run(['bpftool','-j','map','show'],"
         "capture_output=True,text=True).stdout);"
         "print(','.join(str(m['id']) for m in d if'comm_whitelist' in m.get('name','')))"],
        capture_output=True, text=True, timeout=10,
    )
    all_ids = sorted(int(x) for x in r.stdout.strip().split(",") if x)
    return all_ids[-1] if all_ids else -1


# ── hex parsing ───────────────────────────────────────────────────────────────

def parse_hex_byte(s: str) -> int:
    """Parse one hex byte (e.g. "1a") from string, return int or -1."""
    s = s.strip()
    if not s:
        return -1
    try:
        return int(s[:2], 16)
    except ValueError:
        return -1


def parse_hex_dump(text: str) -> List[Dict]:
    """Parse bpftool map dump text output to list of event dicts.

    Text format:
        key:
        <hex bytes>
        value:
        <hex bytes>
        <hex bytes>   (continuation lines for large values)

    Returns list of {"key": ..., "value": bytes}.
    """
    lines = text.splitlines()
    events: List[Dict] = []
    state = "skip"  # skip | key | value
    key_bytes: List[int] = []
    value_bytes: List[int] = []

    for line in lines:
        ls = line.strip()
        if ls == "key:":
            if state == "value" and value_bytes:
                events.append({"key": bytes(key_bytes), "value": bytes(value_bytes)})
            state = "key"
            key_bytes = []
            value_bytes = []
        elif ls == "value:":
            state = "value"
        elif state == "value":
            # Accumulate hex bytes on this line
            p = ls
            while p:
                b = parse_hex_byte(p)
                if b < 0:
                    break
                value_bytes.append(b)
                p = p[2:].lstrip()
                if not p or len(p) < 2:
                    break
                # handle whitespace
                ws = ""
                for ch in p:
                    if ch in " \t\r\n":
                        ws += ch
                    else:
                        break
                p = p[len(ws):]

    # Don't forget last entry
    if state == "value" and value_bytes:
        events.append({"key": bytes(key_bytes), "value": bytes(value_bytes)})

    return events


def _parse_event_bytes(value: bytes) -> Optional[Dict]:
    """Parse 288-byte BPF event struct into dict."""
    if len(value) < 36:
        return None
    import struct
    event_type = struct.unpack_from("<I", value, 0)[0]
    pid = struct.unpack_from("<I", value, 4)[0]
    ts_ns = struct.unpack_from("<Q", value, 8)[0]
    comm = value[16:32].rstrip(b"\x00").decode("utf-8", errors="replace")

    type_map = {1: "FILE", 2: "NET", 3: "DNS"}
    type_str = type_map.get(event_type, f"UNKNOWN({event_type})")

    if type_str == "NET":
        data_bytes = value[32:]
        if len(data_bytes) >= 16:
            family = struct.unpack_from("<H", data_bytes, 0)[0]
            if family == 2:  # AF_INET
                ip = f"{data_bytes[4]}.{data_bytes[5]}.{data_bytes[6]}.{data_bytes[7]}"
                port = struct.unpack_from(">H", data_bytes, 2)[0]
                data_str = f"{ip}:{port}"
            else:
                data_str = f"AF_FAMILY({family})"
        else:
            data_str = ""
    else:
        data = value[32:].rstrip(b"\x00")
        try:
            data_str = data.decode("utf-8", errors="replace")
        except Exception:
            data_str = ""

    return {
        "type": type_str,
        "pid": pid,
        "ts_ns": ts_ns,
        "comm": comm,
        "data": data_str,
    }


def fetch_events(map_id: int) -> List[Dict]:
    """Fetch events from BPF map by ID, return parsed event dicts.

    Uses the fast C bpf_map_dump binary if available (131ms vs 1123ms for bpftool).
    Falls back to bpftool map dump + hex parsing if C binary not found.
    """
    if map_id <= 0:
        return []

    # Try fast C reader first
    if os.path.exists(_BPF_MAP_DUMP):
        try:
            r = subprocess.run(
                [_BPF_MAP_DUMP, str(map_id)],
                capture_output=True, text=True, timeout=10,
            )
            events = []
            for line in r.stdout.splitlines():
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return events
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Fallback: bpftool map dump + hex parsing
    try:
        r = subprocess.run(
            ["bpftool", "map", "dump", "id", str(map_id)],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return []

    raw = parse_hex_dump(r.stdout)
    result: List[Dict] = []
    for e in raw:
        parsed = _parse_event_bytes(e["value"])
        if parsed:
            result.append(parsed)
    return result


def clear_map(map_id: int) -> bool:
    """Delete all entries from a BPF hash map. Returns True on success."""
    try:
        r = subprocess.run(
            ["bpftool", "map", "dump", "id", str(map_id)],
            capture_output=True, text=True, timeout=10,
        )
        lines = r.stdout.splitlines()
        keys: List[str] = []
        in_key = False
        key_hex = ""
        for line in lines:
            ls = line.strip()
            if ls == "key:":
                in_key = True
                key_hex = ""
            elif ls == "value:":
                in_key = False
                if key_hex:
                    keys.append(key_hex)
            elif in_key:
                key_hex += ls.replace(" ", "")

        deleted = 0
        for k in keys:
            subprocess.run(
                ["bpftool", "map", "delete", "id", str(map_id), "key", "hex", k],
                capture_output=True, text=True, timeout=5,
            )
            deleted += 1
        return True
    except Exception:
        return False


def update_whitelist_map(map_id: int, comm: str) -> bool:
    """Add a comm name to the whitelist map."""
    try:
        # Convert comm to 16-byte hex array (pad with zeros)
        comm_bytes = comm.encode('utf-8')[:16].ljust(16, b'\x00')

        # Build command: bpftool map update id <id> key <16 hex bytes> value <4 zeros>
        cmd = ["bpftool", "map", "update", "id", str(map_id), "key"]
        cmd.extend([f"0x{b:02x}" for b in comm_bytes])
        cmd.extend(["value", "0", "0", "0", "0"])

        subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return True
    except Exception:
        return False


def deduplicate_events(
    new_events: List[Dict], seen_keys: Set[int]
) -> tuple:
    """Filter out events already seen (by key=ts_ns). Returns (unique_events, updated_keys)."""
    unique = [e for e in new_events if e["ts_ns"] not in seen_keys]
    for e in unique:
        seen_keys.add(e["ts_ns"])
    return unique, seen_keys
