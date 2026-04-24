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
    cfg = add_target(
        process=args.process,
        file=args.file or [],
        network=args.network or [],
        dns=args.dns or [],
        path=_config_path,
    )
    targets = cfg.get("targets", [])
    t = targets[-1]
    print(f"Added: [{t['id']}] {t['process']}"
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
    print(f"Deleted: [{match['id']}] {match['process']}")


def audit_list(args) -> None:
    targets = list_targets(_config_path)
    if not targets:
        print("(no targets)")
        return
    if args.json:
        print(json.dumps(targets, indent=2))
    else:
        for t in targets:
            print(f"  [{t['id']}] {t['process']}"
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

    p_audit_add = p_audit_sub.add_parser("add", help="Add audit target")
    p_audit_add.add_argument("--process", required=True)
    p_audit_add.add_argument("--file", action="append", default=[])
    p_audit_add.add_argument("--network", action="append", default=[])
    p_audit_add.add_argument("--dns", action="append", default=[])
    p_audit_add.set_defaults(fn=audit_add)

    p_audit_del = p_audit_sub.add_parser("del", help="Delete audit target")
    p_audit_del.add_argument("--process", default=None)
    p_audit_del.add_argument("--id", type=int, default=None)
    p_audit_del.set_defaults(fn=audit_del)

    p_audit_list = p_audit_sub.add_parser("list", help="List audit targets")
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
