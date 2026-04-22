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

    def log_event(self, event: Dict[str, Any]) -> None:
        """Write a single audit event as a JSON line (FILE/NET/DNS only)."""
        record = dict(event)
        # Ensure ts field (for daemon startup/shutdown events)
        if "ts" not in record:
            record["ts"] = datetime.now().isoformat()
        self.logger.info(json.dumps(record, ensure_ascii=False, default=str))

    def log_events_batch(self, events: List[Dict]) -> None:
        """Write multiple events in batch."""
        for event in events:
            self.log_event(event)

    def close(self) -> None:
        """Flush and remove handler."""
        self._handler.close()
        self.logger.removeHandler(self._handler)


class RuntimeLogger:
    """Thread-safe runtime logger for daemon lifecycle events."""

    def __init__(self, log_path: str, max_bytes: int = 10 * 1024 * 1024, backup_count: int = 3):
        self.log_path = log_path
        self._ensure_dir(log_path)

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        self._handler = logging.handlers.RotatingFileHandler(
            filename=log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        self._handler.setFormatter(formatter)

        self.logger = logging.getLogger("agent_runtime")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self._handler)
        self.logger.propagate = False

    def _ensure_dir(self, log_path: str) -> None:
        """Create log directory if needed."""
        dir_path = Path(log_path).parent
        dir_path.mkdir(parents=True, exist_ok=True)

    def info(self, message: str) -> None:
        """Write info-level runtime log."""
        self.logger.info(message)

    def error(self, message: str) -> None:
        """Write error-level runtime log."""
        self.logger.error(message)

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


def make_runtime_logger(log_path: str, max_size_mb: int = 10, backup_count: int = 3) -> RuntimeLogger:
    """Create RuntimeLogger for daemon lifecycle events."""
    return RuntimeLogger(
        log_path=log_path,
        max_bytes=max_size_mb * 1024 * 1024,
        backup_count=backup_count,
    )
