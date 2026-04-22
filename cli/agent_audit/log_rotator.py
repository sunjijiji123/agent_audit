"""Audit log rotator — JSONL output with RotatingFileHandler."""

import json
import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


def _make_day_backup_filename(log_path: str) -> str:
    """Return 'audit_YYYYMMDD.log' based on today's date."""
    date_str = datetime.now().strftime("%Y%m%d")
    base = Path(log_path).name
    return str(Path(log_path).parent / f"{Path(date_str).stem}_{date_str}.log").replace(
        f"_{date_str}.log", f"_{date_str}.log"
    )


import time
_BOOT_TO_EPOCH_NS = time.time_ns() - int(time.clock_gettime(time.CLOCK_BOOTTIME) * 1e9)


class AuditLogger:
    """Thread-safe JSONL logger backed by RotatingFileHandler.

    On rotation, renames current file with a date suffix.
    """

    def __init__(
        self,
        log_path: str,
        max_bytes: int = 50 * 1024 * 1024,  # 50MB
        backup_count: int = 5,
    ):
        self.log_path = log_path
        self._ensure_dir(log_path)

        # Custom formatter outputs one JSON object per line
        formatter = logging.Formatter("%(message)s")

        self._handler = logging.handlers.RotatingFileHandler(
            filename=log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        self._handler.setFormatter(formatter)
        self._handler.rotation_filename = self._rotation_filename

        self.logger = logging.getLogger("agent_audit")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self._handler)
        self.logger.propagate = False

    def _ensure_dir(self, log_path: str) -> None:
        """Create log directory if needed."""
        dir_path = Path(log_path).parent
        dir_path.mkdir(parents=True, exist_ok=True)

    def _rotation_filename(self, default: str) -> str:
        """Return date-stamped backup filename on rotation."""
        date_str = datetime.now().strftime("%Y%m%d")
        base = Path(default).name
        parent = Path(default).parent
        return str(parent / f"{base.rsplit('.', 1)[0]}_{date_str}.log")

    def log_event(self, event: Dict[str, Any], proc_chain: str = "") -> None:
        """Write a single event as a JSON line."""
        record = dict(event)
        record["proc_chain"] = proc_chain
        # Ensure ts field
        if "ts" not in record and "ts_ns" in record:
            from datetime import datetime
            epoch_ns = record["ts_ns"] + _BOOT_TO_EPOCH_NS
            secs = epoch_ns / 1_000_000_000
            record["ts"] = datetime.fromtimestamp(secs).isoformat()
        self.logger.info(json.dumps(record, ensure_ascii=False, default=str))

    def log_events_batch(
        self, events: List[Dict], proc_trees: Dict[int, str]
    ) -> None:
        """Write multiple events in batch."""
        for event in events:
            pid = event.get("pid", 0)
            chain = proc_trees.get(pid, "")
            self.log_event(event, proc_chain=chain)

    def close(self) -> None:
        """Flush and remove handler."""
        self._handler.close()
        self.logger.removeHandler(self._handler)


# ── convenience factory ────────────────────────────────────────────────────────

def make_audit_logger(
    log_path: str,
    max_size_mb: int = 50,
    backup_count: int = 5,
) -> AuditLogger:
    """Create AuditLogger from config parameters."""
    return AuditLogger(
        log_path=log_path,
        max_bytes=max_size_mb * 1024 * 1024,
        backup_count=backup_count,
    )
