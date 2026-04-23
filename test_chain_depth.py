#!/usr/bin/env python3
"""Test process chain depth — fork child and verify chain tracking."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
AUDIT_LOG = "/var/log/agent-audit/audit.log"

MY_PID = os.getpid()


def log(msg):
    print(f"[chain] {msg}")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def run_cli(*args):
    cmd = [sys.executable, "-m", "cli.cli"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))


def clear_log():
    try:
        open(AUDIT_LOG, "w").close()
    except FileNotFoundError:
        pass


def read_events():
    try:
        with open(AUDIT_LOG) as f:
            return [json.loads(line) for line in f if line.strip()]
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def main():
    log(f"My PID: {MY_PID}")

    # Configure: register this PID
    cfg = load_config()
    cfg["agent_pids"] = [MY_PID]
    # Ensure wildcard target exists
    if not any(t.get("file") for t in cfg["targets"]):
        cfg["targets"].append({
            "id": 1, "process": "python3",
            "file": ["*"], "network": ["*"], "dns": ["*"],
            "enabled": True,
        })
    save_config(cfg)

    # Stop existing daemon
    run_cli("daemon", "stop")
    time.sleep(1)

    # Clear log and start daemon
    clear_log()
    result = run_cli("daemon", "start")
    log(f"Daemon start: {result.stdout.strip() or result.stderr.strip()}")
    time.sleep(2)

    # Check daemon running
    result = run_cli("daemon", "status")
    log(f"Daemon status: {result.stdout.strip()}")
    if "Running" not in result.stdout:
        log("ERROR: Daemon not running!")
        return 1

    # ── Trigger chain: python3 → bash → ls ──
    log("Triggering: python3 → os.system('ls /tmp') → bash → ls")
    os.system("ls /tmp > /dev/null")
    time.sleep(2)

    # Read events and find FILE events from non-python3 processes
    events = read_events()
    log(f"Total events: {len(events)}")

    # Show all unique chains
    seen_chains = set()
    for e in events:
        chain = e.get("chain", [])
        chain_key = tuple((n["pid"], n["comm"]) for n in chain)
        if chain_key not in seen_chains:
            seen_chains.add(chain_key)
            depth = e.get("chain_depth", 0)
            chain_str = " → ".join(f"{n['comm']}({n['pid']})" for n in chain)
            log(f"  type={e.get('type'):<5} depth={depth} chain={chain_str}")

    # Look specifically for ls events (should have depth >= 2)
    ls_events = [e for e in events if e.get("process", {}).get("comm") == "ls"]
    bash_events = [e for e in events if e.get("process", {}).get("comm") == "bash"]

    log(f"\nls events: {len(ls_events)}")
    log(f"bash events: {len(bash_events)}")

    if ls_events:
        e = ls_events[0]
        chain = e.get("chain", [])
        log(f"ls chain depth: {e.get('chain_depth')}")
        for i, node in enumerate(chain):
            log(f"  [{i}] pid={node['pid']} comm={node['comm']}")
    else:
        log("No ls events — checking if child was auto-whitelisted...")

    # Stop daemon
    run_cli("daemon", "stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
