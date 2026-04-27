#!/usr/bin/env python3
"""E2E test using the CLI — tests FILE, NET, DNS event capture.

Must be run as root on the BPF-capable machine.
Usage: python3 test_e2e_cli.py
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
AUDIT_LOG = "/var/log/agent-audit/audit.log"
RUNTIME_LOG = ROOT / "logs" / "runtime.log"

MY_PID = os.getpid()


def log(msg):
    print(f"[test] {msg}")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def run_cli(*args):
    cmd = [sys.executable, "-m", "cli.cli"] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def clear_audit_log():
    """Truncate audit log so we only see new events."""
    try:
        open(AUDIT_LOG, "w").close()
    except FileNotFoundError:
        pass


def read_new_events():
    """Read events from audit log that were written since test start."""
    try:
        with open(AUDIT_LOG) as f:
            lines = f.readlines()
        return [json.loads(line) for line in lines if line.strip()]
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def trigger_file_event():
    """Trigger a FILE event (openat syscall)."""
    with open("/tmp/e2e_test_file.txt", "w") as f:
        f.write("e2e test")
    os.remove("/tmp/e2e_test_file.txt")


def trigger_network_event():
    """Trigger a NET event (connect syscall) to local gateway."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("192.168.5.1", 80))
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass  # We only need the connect attempt, not success
    finally:
        try:
            s.close()
        except Exception:
            pass


def trigger_dns_event():
    """Trigger a DNS event (getaddrinfo via libc uprobe)."""
    try:
        socket.getaddrinfo("example.com", 80)
    except (socket.gaierror, OSError):
        pass  # We only need the getaddrinfo call


def main():
    log("=== E2E CLI Test ===")
    log(f"My PID: {MY_PID}")

    # ── Step 1: Clean up and configure ──
    log("Step 1: Configure targets and register PID")

    # Remove duplicate/empty targets, keep only wildcard target
    cfg = load_config()
    cfg["targets"] = [t for t in cfg["targets"]
                       if t.get("file") or t.get("network") or t.get("dns")]
    # Ensure we have at least one wildcard target for python3
    if not cfg["targets"]:
        cfg["targets"].append({
            "id": 1, "process": "python3",
            "file": ["*"], "network": ["*"], "dns": ["*"],
            "enabled": True,
        })
    cfg["agent_pids"] = [MY_PID]
    save_config(cfg)

    out, err, rc = run_cli("audit", "list")
    log(f"Targets:\n{out}")

    # ── Step 2: Stop any existing daemon ──
    log("Step 2: Stop existing daemon")
    out, err, rc = run_cli("daemon", "stop")
    log(f"  {out or err}")
    time.sleep(1)

    # ── Step 3: Clear log and start daemon ──
    log("Step 3: Start daemon")
    clear_audit_log()
    out, err, rc = run_cli("daemon", "start")
    log(f"  {out or err}")
    time.sleep(2)  # Wait for BPF to load and PID to register

    # ── Step 4: Check daemon status ──
    out, err, rc = run_cli("daemon", "status")
    log(f"Step 4: Daemon status: {out}")
    if "Running" not in out:
        log("ERROR: Daemon not running!")
        # Check runtime log
        try:
            with open(RUNTIME_LOG) as f:
                for line in f.readlines()[-10:]:
                    log(f"  runtime: {line.rstrip()}")
        except FileNotFoundError:
            log("  No runtime log found")
        return 1

    # ── Step 5: Trigger events ──
    log("Step 5: Triggering events...")

    log("  FILE event (openat)...")
    trigger_file_event()
    time.sleep(0.5)

    log("  NET event (connect to 192.168.5.1:80)...")
    trigger_network_event()
    time.sleep(0.5)

    log("  DNS event (getaddrinfo)...")
    trigger_dns_event()
    time.sleep(2)  # Wait for daemon to poll

    # ── Step 6: Check audit log ──
    log("Step 6: Checking audit log")
    events = read_new_events()
    log(f"  Total events captured: {len(events)}")

    if not events:
        log("ERROR: No events captured!")
        # Check runtime log for clues
        try:
            with open(RUNTIME_LOG) as f:
                for line in f.readlines()[-15:]:
                    log(f"  runtime: {line.rstrip()}")
        except FileNotFoundError:
            log("  No runtime log found")
        run_cli("daemon", "stop")
        return 1

    # ── Step 7: Verify each event type ──
    file_events = [e for e in events if e.get("eventType") == "fileEvent"]
    net_events = [e for e in events if e.get("eventType") == "networkConnect"]
    dns_events = [e for e in events if e.get("eventType") == "dnsQuery"]

    log(f"  FILE events: {len(file_events)}")
    log(f"  NET  events: {len(net_events)}")
    log(f"  DNS  events: {len(dns_events)}")

    all_ok = True

    # Check FILE events
    if file_events:
        e = file_events[0]
        log(f"  ✓ FILE: filePath='{e.get('filePath', '')}'")
        if not e.get("filePath"):
            log("  ✗ FILE data is empty!")
            all_ok = False
    else:
        log("  ✗ No FILE events!")
        all_ok = False

    # Check NET events — this is the key test
    if net_events:
        e = net_events[0]
        dst = e.get("networkDst", "")
        log(f"  ✓ NET: dst='{dst}'")
        if not dst:
            log("  ✗ NET data is empty!")
            all_ok = False
        else:
            log(f"  ✓ NET data parsed successfully!")
    else:
        log("  ✗ No NET events!")
        all_ok = False

    # Check DNS events
    if dns_events:
        e = dns_events[0]
        log(f"  ✓ DNS: query='{e.get('requestDomain', '')}'")
        if not e.get("requestDomain"):
            log("  ✗ DNS data is empty!")
            all_ok = False
    else:
        log("  ✗ No DNS events!")
        all_ok = False

    # ── Print sample events ──
    log("\n=== Sample Events ===")
    for e in events[:5]:
        log(json.dumps(e, indent=2, ensure_ascii=False))

    # ── Step 8: Stop daemon ──
    log("\nStep 8: Stopping daemon")
    run_cli("daemon", "stop")

    # ── Result ──
    if all_ok:
        log("\n✓ ALL TESTS PASSED")
        return 0
    else:
        log("\n✗ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
