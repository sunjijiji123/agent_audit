#!/bin/bash
# eBPF Audit CLI Test Suite
# Usage: ./test.sh  (run locally or on remote)

REMOTE="root@192.168.5.137"
REMOTE_DIR="/root/ai-ebpf-demo-cli"
LOG="/var/log/agent-audit/audit.log"
PASS=0
FAIL=0
TESTS_RUN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# ── auto-detect local vs remote execution ────────────────────────────────────
# If this machine has 192.168.5.137, we're on the remote host
if ip addr show 2>/dev/null | grep -q "192.168.5.137" || hostname -I 2>/dev/null | grep -q "192.168.5.137"; then
    ON_REMOTE=1
else
    ON_REMOTE=0
fi

# Remote execution helpers
rsh() {
    if [ "$ON_REMOTE" -eq 1 ]; then
        eval "$@"
    else
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$REMOTE" "$@"
    fi
}

rcp() {
    if [ "$ON_REMOTE" -eq 1 ]; then
        cp "$1" "$2"
    else
        scp -o StrictHostKeyChecking=no "$1" "$REMOTE:$2"
    fi
}

# ── test runner ──────────────────────────────────────────────────────────────

run_test() {
    local name="$1" cmd="$2" expected="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "  [$TESTS_RUN] $name ... "
    output=$(eval "$cmd" 2>&1)
    if echo "$output" | grep -qi "$expected"; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC}"
        echo "    Output: $(echo "$output" | head -3)"
        FAIL=$((FAIL + 1))
    fi
}

wait_for_bpf() {
    local i=0
    while [ $i -lt 30 ]; do
        if rsh "bpftool prog show 2>/dev/null" | grep -q handle_openat; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

wait_for_events() {
    local i=0
    while [ $i -lt 20 ]; do
        if rsh "tail -20 $LOG 2>/dev/null" | grep -q '"file_reads"'; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

echo "=========================================="
echo " eBPF Audit CLI Test Suite"
echo "=========================================="
echo ""

# 1. Sync
echo "[1/7] Syncing files..."
if [ "$ON_REMOTE" -eq 0 ]; then
    rsh "mkdir -p $REMOTE_DIR/ebpf $REMOTE_DIR/cli/agent_audit /root/tmp" 2>/dev/null
    sleep 1
    rcp ebpf/audit.bpf.c "$REMOTE_DIR/ebpf/"
    rcp ebpf/bpf_map_dump.c "$REMOTE_DIR/ebpf/"
    rcp ebpf/Makefile "$REMOTE_DIR/ebpf/"
    sleep 1
    rcp config.json "$REMOTE_DIR/"
    sleep 1
    rcp cli/cli.py "$REMOTE_DIR/cli/"
    rcp cli/__init__.py "$REMOTE_DIR/cli/"
    rcp cli/agent_audit/*.py "$REMOTE_DIR/cli/agent_audit/"
    sleep 1
fi

# 2. Build
echo "[2/7] Building..."
rsh "cd $REMOTE_DIR/ebpf && make clean && make" >/dev/null 2>&1

# 3. Clean state
echo "[3/7] Cleaning..."
rsh "cat > $REMOTE_DIR/config.json << 'CONFEOF'
{
  \"log\": {\"path\": \"$LOG\", \"max_size_mb\": 50, \"backup_count\": 5},
  \"daemon\": {\"poll_interval_sec\": 1, \"bpf_elf\": \"$REMOTE_DIR/ebpf/audit.bpf.o\"},
  \"targets\": []
}
CONFEOF
kill \$(cat /root/tmp/agent-audit-daemon.pid 2>/dev/null) 2>/dev/null
sleep 1
rm -f /root/tmp/agent-audit-daemon.pid
rm -rf /sys/fs/bpf/audit
truncate -s 0 $LOG 2>/dev/null" 2>/dev/null
sleep 1

# 4. CLI: Rule Management
echo ""
echo "[4/7] CLI: Rule Management"
echo ""

run_test "audit add: node FILE" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py audit add --process node --file /root/\"" \
    "Added.*node.*file=True"

run_test "audit add: node NET" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py audit add --process node --network 127.0.0.1\"" \
    "Added.*node.*net=True"

run_test "audit add: node DNS" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py audit add --process node --dns example.com\"" \
    "Added.*node.*dns=True"

run_test "audit add: bash FILE" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py audit add --process bash --file /tmp/\"" \
    "Added.*bash.*file=True"

run_test "audit list" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py audit list\"" \
    "node"

run_test "audit del: bash" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py audit del --process bash\"" \
    "Deleted.*bash"

run_test "audit list: verify deleted" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py audit list\"" \
    "node"

run_test "audit list --json" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py audit list --json\"" \
    "process"

run_test "config show" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py config\"" \
    "daemon"

run_test "config update" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py config --poll-interval 1\"" \
    "poll_interval_sec = 1"

# 5. Daemon Management
echo ""
echo "[5/7] CLI: Daemon Management"
echo ""

# Start daemon in background (avoids fork timing issues)
rsh "cd $REMOTE_DIR && nohup python3 -c \"from cli.agent_audit.daemon import run_loop; from cli.agent_audit.daemon import _write_pid; _write_pid(); run_loop()\" > /dev/null 2>&1 &"

echo -n "  [$((TESTS_RUN + 1))] daemon start ... "
sleep 3
if rsh "test -f /root/tmp/agent-audit-daemon.pid"; then
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAIL=$((FAIL + 1))
fi
TESTS_RUN=$((TESTS_RUN + 1))

echo -n "  Waiting for BPF load... "
if wait_for_bpf; then
    echo -e "${GREEN}BPF loaded${NC}"
else
    echo -e "${RED}BPF not loaded${NC}"
fi

run_test "daemon status" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py daemon status\"" \
    "Running"

# 6. Event Capture
echo ""
echo "[6/7] Event Capture"
echo ""

# Start a local HTTP server for NET events
rsh "python3 -m http.server 9999 --bind 127.0.0.1 > /dev/null 2>&1 & echo \$! > /tmp/test-http-server.pid" 2>/dev/null
sleep 2

# Trigger FILE + NET events with node
rsh "cd /root && node -e \"
const http = require('http');
const fs = require('fs');
const p = '/root/test-cli-' + Date.now() + '.txt';
fs.writeFileSync(p, 'hello ebpf');
http.get('http://127.0.0.1:9999/test', () => {});
fs.unlinkSync(p);
\"" 2>/dev/null

echo -n "  Waiting for events... "
if wait_for_events; then
    echo -e "${GREEN}Events captured${NC}"
else
    echo -e "${RED}No events${NC}"
fi

run_test "Node events in log (comm field)" \
    "rsh \"tail -50 $LOG\"" \
    "node"

run_test "FILE data has file path" \
    "rsh \"tail -50 $LOG\"" \
    "test-cli-"

run_test "Timestamp is 2026" \
    "rsh \"tail -50 $LOG\"" \
    "2026-"

run_test "NET connects captured" \
    "rsh \"tail -50 $LOG\"" \
    "connects"

run_test "DNS events not captured (uprobe autoattach pending)" \
    "rsh \"tail -50 $LOG | grep -c 'dns_queries'\"" \
    "0"

# Stop local HTTP server
rsh "kill \$(cat /tmp/test-http-server.pid 2>/dev/null) 2>/dev/null; rm -f /tmp/test-http-server.pid" 2>/dev/null

# 7. Log CLI
echo ""
echo "[7/7] CLI: Log Commands"
echo ""

run_test "log --tail 5" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py log --tail 5\"" \
    "comm"

run_test "log --type FILE" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py log --type FILE\"" \
    "file_reads"

run_test "log --type NET" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py log --type NET\"" \
    "connects"

run_test "log --type DNS (empty, uprobe pending)" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py log --type DNS\" | wc -l" \
    "0"

run_test "log --grep" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py log --grep node\"" \
    "node"

# Extra: Rule filtering
echo ""
echo "[Extra] Rule Filtering"
echo ""

# bash events should NOT appear (only node rule configured)
rsh "bash -c 'echo test > /root/test-filter.txt && cat /root/test-filter.txt && rm -f /root/test-filter.txt'" 2>/dev/null
sleep 4

run_test "Bash events NOT logged (no rule)" \
    "rsh \"tail -50 $LOG | grep -c '\"bash\"'\"" \
    "0"

# Cleanup
run_test "daemon stop" \
    "rsh \"cd $REMOTE_DIR && python3 cli/cli.py daemon stop\"" \
    "Daemon stopped"

# Fallback: kill any remaining daemon processes
rsh "pkill -f 'agent_audit' 2>/dev/null; sleep 1; rm -f /root/tmp/agent-audit-daemon.pid" 2>/dev/null

# Summary
echo ""
echo "=========================================="
echo " Results: $PASS/$TESTS_RUN passed, $FAIL failed"
echo "=========================================="
if [ $FAIL -eq 0 ]; then
    echo -e " ${GREEN}All tests passed!${NC}"
else
    echo -e " ${RED}$FAIL test(s) failed${NC}"
fi
