#!/bin/bash
# Deploy and restart eBPF audit daemon on remote machine
# Usage: ./deploy.sh
# Override defaults: REMOTE=root@10.0.0.1 REMOTE_DIR=/opt/app ./deploy.sh

REMOTE="${REMOTE:-root@192.168.5.137}"
REMOTE_DIR="${REMOTE_DIR:-/mnt/hgfs/code/1-ai/ai-ebpf-demo-cli}"
PID_DIR="${PID_DIR:-/tmp/agent-audit}"
LOG_PATH="${LOG_PATH:-/var/log/agent-audit/audit.log}"

echo "=== 1. Syncing files ==="
ssh $REMOTE "mkdir -p $REMOTE_DIR/ebpf $REMOTE_DIR/cli/agent_audit $PID_DIR"

scp ebpf/audit.bpf.c $REMOTE:$REMOTE_DIR/ebpf/
scp ebpf/bpf_map_dump.c $REMOTE:$REMOTE_DIR/ebpf/
scp ebpf/Makefile $REMOTE:$REMOTE_DIR/ebpf/
scp cli/cli.py $REMOTE:$REMOTE_DIR/cli/
scp cli/agent_audit/*.py $REMOTE:$REMOTE_DIR/cli/agent_audit/
scp config.json $REMOTE:$REMOTE_DIR/

echo "=== 2. Building ==="
ssh $REMOTE "cd $REMOTE_DIR/ebpf && make clean && make"

echo "=== 3. Restarting daemon ==="
ssh $REMOTE "pkill -f agent_audit 2>/dev/null; sleep 1; rm -f $PID_DIR/daemon.pid; rm -rf /sys/fs/bpf/audit; > $LOG_PATH; cd $REMOTE_DIR; python3 cli/cli.py daemon start"

echo "=== 4. Verifying ==="
ssh $REMOTE "echo 'PID:' && cat $PID_DIR/daemon.pid && echo '' && echo 'BPF:' && bpftool prog show | grep handle"

echo "=== Deploy complete ==="
