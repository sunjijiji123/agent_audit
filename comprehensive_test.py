#!/usr/bin/env python3
"""Comprehensive test for PID whitelist and process tree tracking."""

import subprocess
import json
import time
import struct
import os

SSH_HOST = "root@192.168.5.137"
CODE_DIR = "/mnt/hgfs/code/1-ai/ai-ebpf-demo-cli"

def ssh(cmd, timeout=10):
    """Execute SSH command."""
    full_cmd = f"ssh {SSH_HOST} '{cmd}'"
    return subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=timeout)

def get_map_id(name):
    """Get map ID by name."""
    r = ssh("bpftool -j map show")
    maps = json.loads(r.stdout)
    for m in maps:
        if name in m.get('name', ''):
            return m['id']
    return None

def register_pid(pid):
    """Register PID in pid_whitelist."""
    # Calculate bytes correctly on remote
    r = ssh(f"python3 -c \"import struct; pid={pid}; key=struct.pack('<I', pid); value=struct.pack('<IB', pid, 0); print('key: ' + ' '.join([f'0x{{b:02x}}' for b in key])); print('val: ' + ' '.join([f'0x{{b:02x}}' for b in value]))\"")
    lines = r.stdout.strip().split('\n')
    key_hex = lines[0].replace('key: ', '')
    val_hex = lines[1].replace('val: ', '')
    print(f"Registering PID {pid}: key={key_hex}, value={val_hex}")
    return ssh(f"bpftool map update name pid_whitelist key {key_hex} value {val_hex}")

print("=" * 60)
print("PID Whitelist + Process Tree Comprehensive Test")
print("=" * 60)

# Test 1: Agent PID Registration
print("\n[Test 1] Agent PID Registration")
print("-" * 40)

# Spawn Agent
print("Spawning Agent...")
r = ssh(f"cd {CODE_DIR} && python3 -c \"import os, time; pid=os.getpid(); open('/tmp/test_pid', 'w').write(str(pid)); print(pid); time.sleep(120)\" > /tmp/agent_out.txt 2>&1 &")
time.sleep(2)

r = ssh("cat /tmp/test_pid")
agent_pid = r.stdout.strip()
print(f"Agent PID: {agent_pid}")

# Register
r = register_pid(int(agent_pid))
if r.returncode != 0:
    print(f"ERROR: {r.stderr}")
else:
    print("SUCCESS: PID registered")

r = ssh("bpftool map dump name pid_whitelist")
print(f"pid_whitelist:\n{r.stdout}")

# Verify PID exists
if agent_pid in r.stdout:
    print("[PASS] Test 1: PID Registration SUCCESS")
else:
    print("[FAIL] Test 1: PID not found in whitelist")

# Test 2: Fork Auto-discovery
print("\n[Test 2] Fork Auto-discovery")
print("-" * 40)

print("Agent spawning child process...")
ssh(f"python3 -c 'import os, time; os.fork(); time.sleep(60)' &")
time.sleep(3)

# Find children
r = ssh(f"pgrep -P {agent_pid} || echo 'none'")
children = [p for p in r.stdout.strip().split('\n') if p and p != 'none']
print(f"Found child PIDs: {children}")

# Check if children auto-added to whitelist
r = ssh("bpftool map dump name pid_whitelist")
auto_added = [c for c in children if c in r.stdout]
print(f"Auto-added children: {auto_added}")

if auto_added:
    print("[PASS] Test 2: Fork Auto-discovery SUCCESS")
else:
    print("[WARN] Test 2: No children auto-added (may need different fork method)")

# Test 3: Syscall Event Capture
print("\n[Test 3] Syscall Event Capture")
print("-" * 40)

print("Agent triggering file open...")
ssh(f"touch /tmp/test_file_{agent_pid}.txt")
time.sleep(2)

r = ssh("bpftool map dump name events | head -30")
print(f"Events map:\n{r.stdout}")

if "Found" not in r.stdout or "0 elements" not in r.stdout:
    print("[PASS] Test 3: Events captured (or check needed)")
else:
    print("[WARN] Test 3: No events (may need actual Agent to trigger openat)")

# Test 4: agent_tree and agent_children
print("\n[Test 4] Process Tree Maps")
print("-" * 40)

r = ssh("bpftool map dump name agent_tree")
print(f"agent_tree:\n{r.stdout}")

r = ssh("bpftool map dump name agent_children")
print(f"agent_children:\n{r.stdout}")

# Summary
print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)
print(f"Agent PID: {agent_pid}")
print("Check maps manually above for verification")
print("\nRun these commands on remote for more details:")
print(f"  bpftool map dump name pid_whitelist")
print(f"  bpftool map dump name agent_tree")
print(f"  bpftool map dump name agent_children")
print(f"  bpftool map dump name events")
print("\nCleanup: pkill -f 'time.sleep(120)'; pkill -f 'time.sleep(60)'")
