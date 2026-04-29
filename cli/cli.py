"""agent-audit CLI — unified interface for daemon and audit rules."""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from cli.agent_audit.config import (
    load_config, save_config, add_target, del_target,
    list_targets, update_log_config,
)

from cli.agent_audit.config import _get_config_path
_config_path = str(_get_config_path())


# ── daemon ────────────────────────────────────────────────────────────────────

def daemon_cmd(args) -> None:
    action = args.action

    if action == "start":
        from cli.agent_audit.daemon import DaemonRunner
        runner = DaemonRunner()
        runner.start()

    elif action == "stop":
        try:
            with open("/tmp/agent-audit-daemon.pid") as f:
                pid = int(f.read().strip())
        except Exception:
            print("Daemon not running (no PID file)")
            return

        if not os.path.exists(f"/proc/{pid}"):
            print("Daemon not running")
            try:
                os.unlink("/tmp/agent-audit-daemon.pid")
            except FileNotFoundError:
                pass
            return

        os.kill(pid, 15)
        for _ in range(50):
            if not os.path.exists(f"/proc/{pid}"):
                break
            time.sleep(0.1)
        try:
            os.unlink("/tmp/agent-audit-daemon.pid")
        except FileNotFoundError:
            pass
        print("Daemon stopped")

    elif action == "status":
        try:
            with open("/tmp/agent-audit-daemon.pid") as f:
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

def audit_add(args) -> None:
    if args.processpath and not args.processpath.strip():
        print("Error: --processpath cannot be empty")
        sys.exit(1)
    try:
        cfg = add_target(
            process=args.process,
            file=args.file or [],
            network=args.network or [],
            dns=args.dns or [],
            processpath=args.processpath,
            path=_config_path,
        )
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    targets = cfg.get("targets", [])
    t = targets[-1]
    if t.get("process"):
        identifier = f"process={t['process']}"
    else:
        identifier = f"path={t['processpath']}"
    print(f"Added: [{t['id']}] {identifier}"
          f"  file={bool(t.get('file'))}"
          f"  net={bool(t.get('network'))}"
          f"  dns={bool(t.get('dns'))}")


def audit_del(args) -> None:
    cfg = load_config(_config_path)
    targets = cfg.get("targets", [])
    match = None
    for t in targets:
        if args.id and t.get("id") == args.id:
            match = t
            break
        elif args.process and t.get("process") == args.process:
            match = t
            break

    if not match:
        print(f"Target not found: {args.id or args.process}")
        sys.exit(1)

    cfg["targets"] = [t for t in targets if t.get("id") != match["id"]]
    save_config(cfg, _config_path)
    label = match.get("process") or match.get("processpath", "")
    print(f"Deleted: [{match['id']}] {label}")


def audit_list(args) -> None:
    targets = list_targets(_config_path)
    if not targets:
        print("(no targets)")
        return
    if args.json:
        print(json.dumps(targets, indent=2))
    else:
        for t in targets:
            if t.get("process"):
                identifier = f"process={t['process']}"
            else:
                identifier = f"path={t['processpath']}"
            print(f"  [{t['id']}] {identifier}"
                  f"  file={bool(t.get('file'))}"
                  f"  net={bool(t.get('network'))}"
                  f"  dns={bool(t.get('dns'))}"
                  f"  enabled={t.get('enabled', True)}")


# ── log ───────────────────────────────────────────────────────────────────────

def log_cmd(args) -> None:
    cfg = load_config(_config_path)
    log_path = cfg.get("log", {}).get("path", "/var/log/agent-audit/audit.log")

    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        sys.exit(1)

    with open(log_path, encoding="utf-8") as f:
        lines = f.readlines()

    # Read range: --tail N, --cat (all), or default last 20
    if args.tail:
        lines = lines[-args.tail:]
    elif not args.cat:
        lines = lines[-20:]

    # Content filters (composable)
    if args.grep:
        lines = [line for line in lines if args.grep in line]
    if args.type_filter:
        type_map = {
            "FILE": '"eventType":"fileEvent"',
            "NET": '"eventType":"networkConnect"',
            "DNS": '"eventType":"dnsQuery"',
            "FORK": '"eventType":"processCreate"',
        }
        marker = type_map[args.type_filter]
        lines = [line for line in lines if marker in line]

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

    p_audit_add = p_audit_sub.add_parser("add", help="Add audit target")
    add_group = p_audit_add.add_mutually_exclusive_group(required=True)
    add_group.add_argument("--process", help="Match by process comm name")
    add_group.add_argument("--processpath", help="Match by executable path (glob)")
    p_audit_add.add_argument("--file", action="append", default=[])
    p_audit_add.add_argument("--network", action="append", default=[])
    p_audit_add.add_argument("--dns", action="append", default=[])
    p_audit_add.set_defaults(fn=audit_add)

    p_audit_del = p_audit_sub.add_parser("del", help="Delete audit target")
    del_group = p_audit_del.add_mutually_exclusive_group(required=True)
    del_group.add_argument("--process", help="Delete by process comm name")
    del_group.add_argument("--id", type=int, help="Delete by target ID")
    p_audit_del.set_defaults(fn=audit_del)

    p_audit_list = p_audit_sub.add_parser("list", help="List audit targets")
    p_audit_list.add_argument("--json", action="store_true")
    p_audit_list.set_defaults(fn=audit_list)

    # log
    p_log = sub.add_parser("log", help="Read audit log")
    range_group = p_log.add_mutually_exclusive_group()
    range_group.add_argument("--tail", type=int, metavar="N")
    range_group.add_argument("--cat", action="store_true")
    p_log.add_argument("--grep", metavar="STR")
    p_log.add_argument("--type", dest="type_filter", choices=["FILE", "NET", "DNS", "FORK"])
    p_log.set_defaults(fn=log_cmd)

    # config
    p_conf = sub.add_parser("config", help="View/update config")
    p_conf.add_argument("--log-path", metavar="PATH")
    p_conf.add_argument("--log-size", type=int, metavar="MB")
    p_conf.add_argument("--log-backup", type=int, metavar="N")
    p_conf.set_defaults(fn=config_cmd)

    args = parser.parse_args()

    args.fn(args)


if __name__ == "__main__":
    main()
