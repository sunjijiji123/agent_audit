"""agent_audit - Python Daemon for AI Agent Process Auditing via eBPF.

Modules:
    config      — Read/write config.json
    bpf_reader  — bpftool loadall/map dump wrapper, hex parsing, dedup
    matcher     — Rule matching (filter events by process comm)
    log_rotator — RotatingFileHandler for JSONL audit logs
"""

__version__ = "0.1.0"
