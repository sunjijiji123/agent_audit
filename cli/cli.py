"""agent-audit CLI — unified interface for daemon and audit rules."""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from cli.agent_audit.config import (
    load_config, save_config, add_agent, del_agent,
    list_agents, update_log_config, DEFAULT_LOG_PATH,
)
from cli.agent_audit.daemon import _PID_FILE

_root = Path(__file__).resolve().parent.parent
_config_path = str(_root / "config.json")


# ── daemon ────────────────────────────────────────────────────────────────────

def daemon_cmd(args) -> None:
    action = args.action

    if action == "start":
        pid = os.fork()
        if pid == 0:
            os.close(0)
            os.close(1)
            os.close(2)
            os.open(os.devnull, os.O_RDWR)
            os.dup2(0, 1)
            os.dup2(0, 2)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(_root)
            os.chdir("/")
            os.execvpe(
                sys.executable,
                [sys.executable, "-m", "cli.agent_audit", "start"],
                env,
            )
        else:
            time.sleep(0.6)
            try:
                with open(_PID_FILE) as f:
                    daemon_pid = int(f.read().strip())
                if os.path.exists(f"/proc/{daemon_pid}"):
                    print(f"Daemon started (PID {daemon_pid})")
                else:
                    print("Daemon process exited — check logs")
            except Exception:
                print("Could not verify daemon status")

    elif action == "stop":
        try:
            with open(_PID_FILE) as f:
                pid = int(f.read().strip())
        except Exception:
            print("Daemon not running (no PID file)")
            return

        if not os.path.exists(f"/proc/{pid}"):
            print("Daemon not running")
            try:
                os.unlink(_PID_FILE)
            except FileNotFoundError:
                pass
            return

        os.kill(pid, 15)
        for _ in range(50):
            if not os.path.exists(f"/proc/{pid}"):
                break
            time.sleep(0.1)
        try:
            os.unlink(_PID_FILE)
        except FileNotFoundError:
            pass
        print("Daemon stopped")

    elif action == "status":
        try:
            with open(_PID_FILE) as f:
                pid = int(f.read().strip())
            if os.path.exists(f"/proc/{pid}"):
                print(f"Running (PID {pid})")
            else:
                print("Stale PID file — daemon not running")
        except FileNotFoundError:
            print("Daemon not running")
        except ValueError:
            print("Corrupt PID file")


# ── audit ─────────────────────────────────────────────────────────────────────

def _find_pids_by_process(process_name: str) -> list:
    """Scan /proc to find PIDs by comm name."""
    pids = []
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        try:
            with open(f"/proc/{pid_str}/comm", "r") as f:
                comm = f.read().strip()
            if comm == process_name:
                pids.append(int(pid_str))
        except (FileNotFoundError, PermissionError):
            continue
    return pids


def audit_add(args) -> None:
    if args.pid:
        pids = [args.pid]
        source = f"PID {args.pid}"
    elif args.process:
        pids = _find_pids_by_process(args.process)
        source = f"process '{args.process}'"
        if not pids:
            print(f"No running processes found for: {args.process}")
            sys.exit(1)
    else:
        print("Either --pid or --process is required")
        sys.exit(1)

    added = []
    for pid in pids:
        cfg = add_agent(pid, _config_path)
        added.append(pid)

    if len(added) > 1:
        print(f"Added {len(added)} PIDs from {source}: {added}")
    else:
        print(f"Added agent PID: {added[0]}")


def _bpf_map_delete_pid(map_name: str, pid: int) -> bool:
    """Delete a PID from BPF map using bpftool."""
    try:
        # Convert PID to little-endian 4-byte hex
        key_hex = " ".join(f"0x{(pid >> (i*8)) & 0xff:02x}" for i in range(4))
        result = subprocess.run(
            ["bpftool", "map", "delete", "name", map_name, "key", *key_hex.split()],
            capture_output=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def audit_del(args) -> None:
    # Check if PID exists in BPF map first
    whitelist = _bpf_map_dump("pid_whitelist")
    if whitelist is None:
        print("Daemon not running or pid_whitelist map not found")
        sys.exit(1)

    found = False
    for entry in whitelist:
        formatted = entry.get("formatted", {})
        if formatted.get("key", 0) == args.pid:
            found = True
            break

    if not found:
        print(f"Agent PID {args.pid} not found in whitelist")
        sys.exit(1)

    # Remove from BPF map
    if _bpf_map_delete_pid("pid_whitelist", args.pid):
        print(f"Deleted agent PID: {args.pid}")
    else:
        print(f"Failed to delete agent PID: {args.pid}")
        sys.exit(1)


def _bpf_map_dump(map_name: str) -> Optional[list]:
    """Dump BPF map using bpftool, return parsed list. Return None on error."""
    try:
        result = subprocess.run(
            ["bpftool", "map", "dump", "name", map_name, "-j"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def audit_list(args) -> None:
    # Read pid_whitelist map
    whitelist = _bpf_map_dump("pid_whitelist")
    if whitelist is None:
        print("Daemon not running or pid_whitelist map not found")
        return

    agents = []
    for entry in whitelist:
        # bpftool format: {"formatted": {"key": 1, "value": {"root_pid": 1, "depth": 0}}}
        formatted = entry.get("formatted", {})
        pid = formatted.get("key", 0)
        value = formatted.get("value", {})
        root_pid = value.get("root_pid", 0)
        depth = value.get("depth", 0)

        # Try to read comm from /proc
        comm = ""
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                comm = f.read().strip()
        except (FileNotFoundError, PermissionError):
            pass

        agents.append({
            "pid": pid,
            "comm": comm,
            "root_pid": root_pid,
            "depth": depth,
        })

    if args.json:
        print(json.dumps(agents, indent=2))
    else:
        if not agents:
            print("(no agents registered)")
            return
        print(f"Registered agents ({len(agents)}):")
        print(f"  {'PID':<8} {'COMM':<16} {'DEPTH':<6} {'ROOT_PID'}")
        for a in agents:
            print(f"  {a['pid']:<8} {a['comm']:<16} {a['depth']:<6} {a['root_pid']}")


# ── log ───────────────────────────────────────────────────────────────────────

def log_cmd(args) -> None:
    cfg = load_config(_config_path)
    log_path = cfg.get("log", {}).get("path", DEFAULT_LOG_PATH)

    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        sys.exit(1)

    if args.tail:
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()
        lines = lines[-args.tail:]
    elif args.grep:
        with open(log_path, encoding="utf-8") as f:
            lines = [line for line in f if args.grep in line]
    elif args.type_filter:
        type_map = {"FILE": '"type":"FILE"', "NET": '"type":"NET"', "DNS": '"type":"DNS"'}
        marker = type_map.get(args.type_filter, '')
        with open(log_path, encoding="utf-8") as f:
            lines = [line for line in f if marker in line]
    elif args.cat:
        with open(log_path, encoding="utf-8") as f:
            print(f.read(), end="")
        return
    else:
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()
        lines = lines[-20:]

    for line in lines:
        print(line, end="")


# ── config ─────────────────────────────────────────────────────────────────────

def config_cmd(args) -> None:
    cfg = load_config(_config_path)
    updated = False

    if args.log_path:
        cfg.setdefault("log", {})["path"] = args.log_path
        print(f"log.path = {args.log_path}")
        updated = True
    if args.log_size:
        cfg.setdefault("log", {})["max_size_mb"] = args.log_size
        print(f"log.max_size_mb = {args.log_size}")
        updated = True
    if args.log_backup:
        cfg.setdefault("log", {})["backup_count"] = args.log_backup
        print(f"log.backup_count = {args.log_backup}")
        updated = True
    if args.bpf_elf:
        cfg.setdefault("daemon", {})["bpf_elf"] = args.bpf_elf
        print(f"daemon.bpf_elf = {args.bpf_elf}")
        updated = True
    if args.poll_interval:
        cfg.setdefault("daemon", {})["poll_interval_sec"] = args.poll_interval
        print(f"daemon.poll_interval_sec = {args.poll_interval}")
        updated = True

    if updated:
        save_config(cfg, _config_path)
    else:
        print(json.dumps(cfg, indent=2))


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent-audit",
        description="AI Agent process audit CLI (eBPF + Python)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # daemon
    p_daemon = sub.add_parser("daemon", help="Manage audit daemon")
    p_daemon.add_argument("action", choices=["start", "stop", "status"])
    p_daemon.set_defaults(fn=daemon_cmd)

    # audit
    p_audit = sub.add_parser("audit", help="Manage audit targets")
    p_audit_sub = p_audit.add_subparsers(dest="audit_action", required=True)

    p_audit_add = p_audit_sub.add_parser("add", help="Register agent PID for audit")
    p_audit_add_group = p_audit_add.add_mutually_exclusive_group(required=True)
    p_audit_add_group.add_argument("--pid", type=int, help="Direct PID to register")
    p_audit_add_group.add_argument("--process", help="Process name to find and register")
    p_audit_add.set_defaults(fn=audit_add)

    p_audit_del = p_audit_sub.add_parser("del", help="Unregister agent PID")
    p_audit_del.add_argument("--pid", type=int, required=True, help="PID to unregister")
    p_audit_del.set_defaults(fn=audit_del)

    p_audit_list = p_audit_sub.add_parser("list", help="List registered agent PIDs")
    p_audit_list.add_argument("--json", action="store_true")
    p_audit_list.set_defaults(fn=audit_list)

    # log
    p_log = sub.add_parser("log", help="Read audit log")
    p_log.add_argument("--tail", type=int, metavar="N")
    p_log.add_argument("--grep", metavar="STR")
    p_log.add_argument("--type", dest="type_filter", choices=["FILE", "NET", "DNS"])
    p_log.add_argument("--cat", action="store_true")
    p_log.set_defaults(fn=log_cmd)

    # config
    p_conf = sub.add_parser("config", help="View/update config")
    p_conf.add_argument("--log-path", metavar="PATH")
    p_conf.add_argument("--log-size", type=int, metavar="MB")
    p_conf.add_argument("--log-backup", type=int, metavar="N")
    p_conf.add_argument("--bpf-elf", metavar="PATH")
    p_conf.add_argument("--poll-interval", type=float, metavar="SEC")
    p_conf.set_defaults(fn=config_cmd)

    args = parser.parse_args()

    if args.cmd == "audit":
        args.fn(args)
    else:
        args.fn(args)


if __name__ == "__main__":
    main()
