"""Config reader/writer for config.json (project root)."""

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

# Project root (3 levels up from this file: config.py -> agent_audit -> cli -> root)
_ROOT = Path(__file__).resolve().parent.parent.parent

# Path to config.json — relative to project root
_CONFIG_NAME = "config.json"
_CONFIG_PATH = _ROOT / _CONFIG_NAME

# Default log path (single source of truth)
DEFAULT_LOG_PATH = "/var/log/agent-audit/audit.log"

DEFAULT_CONFIG = {
    "log": {
        "path": DEFAULT_LOG_PATH,
        "max_size_mb": 50,
        "backup_count": 5,
    },
    "daemon": {
        "poll_interval_sec": 2,
        "bpf_elf": str(_ROOT / "ebpf" / "audit.bpf.o"),
    },
    "agents": [],
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


def add_agent(pid: int, path: Optional[str] = None) -> dict:
    """Add an agent PID to config.agents. Returns updated config."""
    cfg = load_config(path)
    agents = cfg.setdefault("agents", [])
    if not any(a.get("pid") == pid for a in agents):
        agents.append({"pid": pid})
        save_config(cfg, path)
    return cfg


def del_agent(pid: int, path: Optional[str] = None) -> dict:
    """Remove an agent PID from config.agents. Returns updated config."""
    cfg = load_config(path)
    cfg["agents"] = [a for a in cfg.get("agents", []) if a.get("pid") != pid]
    save_config(cfg, path)
    return cfg


def list_agents(path: Optional[str] = None) -> list:
    """Return all agent PIDs from config."""
    cfg = load_config(path)
    return [a.get("pid") for a in cfg.get("agents", []) if a.get("pid")]


def clear_agents(path: Optional[str] = None) -> dict:
    """Clear all agents from config. Returns updated config."""
    cfg = load_config(path)
    cfg["agents"] = []
    save_config(cfg, path)
    return cfg


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
