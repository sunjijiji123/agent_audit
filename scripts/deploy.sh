#!/bin/bash
# Deploy and restart eBPF audit daemon on remote machine
# Usage: ./deploy.sh

REMOTE="root@192.168.5.137"
REMOTE_DIR="/root/ai-ebpf-demo-cli"

echo "=== 1. Syncing files ==="
ssh $REMOTE "mkdir -p $REMOTE_DIR/ebpf $REMOTE_DIR/cli/agent_audit /root/tmp"

scp ebpf/audit.bpf.c $REMOTE:$REMOTE_DIR/ebpf/
scp ebpf/bpf_map_dump.c $REMOTE:$REMOTE_DIR/ebpf/
scp ebpf/Makefile $REMOTE:$REMOTE_DIR/ebpf/
scp cli/cli.py $REMOTE:$REMOTE_DIR/cli/
scp cli/agent_audit/*.py $REMOTE:$REMOTE_DIR/cli/agent_audit/
scp config.json $REMOTE:$REMOTE_DIR/

echo "=== 2. Building ==="
ssh $REMOTE "cd $REMOTE_DIR/ebpf && make clean && make"

echo "=== 3. Restarting daemon ==="
ssh $REMOTE "pkill -f agent_audit 2>/dev/null; sleep 1; rm -f /root/tmp/agent-audit-daemon.pid; rm -rf /sys/fs/bpf/audit; > /var/log/agent-audit/audit.log; cd $REMOTE_DIR; python3 cli/cli.py daemon start"

echo "=== 4. Verifying ==="
ssh $REMOTE "echo 'PID:' && cat /root/tmp/agent-audit-daemon.pid && echo '' && echo 'BPF:' && bpftool prog show | grep handle"

echo "=== Deploy complete ==="
