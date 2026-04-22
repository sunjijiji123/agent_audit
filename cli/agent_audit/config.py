"""Config reader/writer for config.json (project root)."""

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

# Path to config.json — relative to this file's parent project root
_CONFIG_NAME = "config.json"
_CONFIG_PATH = Path(__file__).resolve().parent.parent / _CONFIG_NAME

DEFAULT_CONFIG = {
    "log": {
        "path": "/var/log/agent-audit/audit.log",
        "max_size_mb": 50,
        "backup_count": 5,
    },
    "daemon": {
        "poll_interval_sec": 2,
        "bpf_elf": "/root/ai-ebpf-demo-cli/ebpf/audit.bpf.o",
        "bpf_map_id": None,
    },
    "targets": [],
}


def load_config(path: Optional[str] = None) -> dict:
    """Load config.json, return dict. Returns DEFAULT_CONFIG if file missing."""
    config_path = Path(path) if path else _CONFIG_PATH
    if not config_path.exists():
        return dict(DEFAULT_CONFIG)
    with open(config_path, encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict, path: Optional[str] = None) -> None:
    """Atomically write config.json: write to temp file then rename."""
    config_path = Path(path) if path else _CONFIG_PATH
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=config_path.parent, prefix=".config_tmp_", suffix=".json"
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        shutil.move(tmp_path, str(config_path))
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def next_target_id(cfg: dict) -> int:
    """Return next unused target id."""
    existing = [t.get("id", 0) for t in cfg.get("targets", [])]
    return max(existing) + 1 if existing else 1


def add_target(
    process: str,
    file: Optional[list] = None,
    network: Optional[list] = None,
    dns: Optional[list] = None,
    path: Optional[str] = None,
) -> dict:
    """Add a new audit target. Returns the updated config."""
    cfg = load_config(path)
    new_id = next_target_id(cfg)
    target = {
        "id": new_id,
        "process": process,
        "file": file or [],
        "network": network or [],
        "dns": dns or [],
        "enabled": True,
    }
    cfg.setdefault("targets", []).append(target)
    save_config(cfg, path)
    return cfg


def del_target(process: str, path: Optional[str] = None) -> dict:
    """Delete all targets matching process name. Returns updated config."""
    cfg = load_config(path)
    original = len(cfg.get("targets", []))
    cfg["targets"] = [t for t in cfg.get("targets", []) if t.get("process") != process]
    save_config(cfg, path)
    return cfg


def list_targets(path: Optional[str] = None) -> list:
    """Return all enabled targets."""
    cfg = load_config(path)
    return [t for t in cfg.get("targets", []) if t.get("enabled", True)]


def update_log_config(
    path: Optional[str] = None,
    log_path: Optional[str] = None,
    max_size_mb: Optional[int] = None,
    backup_count: Optional[int] = None,
) -> dict:
    """Update log configuration fields. Returns updated config."""
    cfg = load_config(path)
    if log_path is not None:
        cfg.setdefault("log", {})["path"] = log_path
    if max_size_mb is not None:
        cfg.setdefault("log", {})["max_size_mb"] = max_size_mb
    if backup_count is not None:
        cfg.setdefault("log", {})["backup_count"] = backup_count
    save_config(cfg, path)
    return cfg
