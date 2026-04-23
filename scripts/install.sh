#!/bin/bash
# Install script for eBPF audit agent
# Installs to /usr/local/agent_audit with system-wide configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

INSTALL_DIR="/usr/local/agent_audit"
CONFIG_DIR="/etc/agent_audit"
LOG_DIR="/var/log/agent-audit"
BIN_DIR="/usr/local/bin"

echo "=== Installing eBPF Audit Agent ==="
echo ""

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (use sudo)"
    exit 1
fi

# Check if built
if [ ! -f "$PROJECT_ROOT/ebpf/audit.bpf.o" ]; then
    echo "ERROR: BPF program not built."
    echo "       Run: cd $PROJECT_ROOT/ebpf && make"
    exit 1
fi

# Create directories
echo "Creating installation directories..."
mkdir -p "$INSTALL_DIR/ebpf"
mkdir -p "$INSTALL_DIR/cli"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Install BPF program
echo "Installing BPF program..."
cp "$PROJECT_ROOT/ebpf/audit.bpf.o" "$INSTALL_DIR/ebpf/"

# Install static map reader (no dependencies)
if [ -f "$PROJECT_ROOT/ebpf/bpf_map_dump-static" ]; then
    cp "$PROJECT_ROOT/ebpf/bpf_map_dump-static" "$INSTALL_DIR/ebpf/bpf_map_dump"
else
    cp "$PROJECT_ROOT/ebpf/bpf_map_dump" "$INSTALL_DIR/ebpf/"
fi
chmod +x "$INSTALL_DIR/ebpf/bpf_map_dump"

# Install Python CLI
echo "Installing Python CLI..."
cp -r "$PROJECT_ROOT/cli" "$INSTALL_DIR/"
cp "$PROJECT_ROOT/pyproject.toml" "$INSTALL_DIR/" 2>/dev/null || true
cp "$PROJECT_ROOT/requirements.txt" "$INSTALL_DIR/" 2>/dev/null || true

# Install or migrate configuration
CONFIG_FILE="$CONFIG_DIR/config.json"
if [ -f "$CONFIG_FILE" ]; then
    echo "Backing up existing config to $CONFIG_FILE.bak..."
    cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
    echo "Migrating targets -> agents config..."
    python3 -c "
import json
with open('$CONFIG_FILE') as f:
    cfg = json.load(f)
# Migrate targets -> agents if needed
if 'targets' in cfg and 'agents' not in cfg:
    cfg['agents'] = cfg.pop('targets')
    with open('$CONFIG_FILE', 'w') as f:
        json.dump(cfg, f, indent=2)
    print('  Config migrated: targets -> agents')
else:
    print('  Config already uses agents format')
"
else
    echo "Installing default configuration..."
    cat > "$CONFIG_FILE" << 'EOF'
{
  "log_file": "/var/log/agent-audit/audit.log",
  "daemon": {
    "pid_file": "/var/run/agent-audit.pid",
    "poll_interval_ms": 100,
    "bpf_map_id": null
  },
  "agents": []
}
EOF
fi

# Create wrapper script
echo "Creating executable wrapper..."
cat > "$BIN_DIR/agent-audit" << EOF
#!/bin/bash
export AGENT_AUDIT_CONFIG="$CONFIG_FILE"
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
python3 -m cli.agent_audit "\$@"
EOF
chmod +x "$BIN_DIR/agent-audit"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Installed to:"
echo "  - $INSTALL_DIR/          (main program)"
echo "  - $CONFIG_DIR/config.json (configuration)"
echo "  - $LOG_DIR/              (audit logs)"
echo "  - $BIN_DIR/agent-audit   (executable wrapper)"
echo ""
echo "Next steps:"
echo "  1. Edit config: sudo vi $CONFIG_DIR/config.json"
echo "  2. Add agents: sudo agent-audit add --pid <pid>"
echo "  3. Start daemon: sudo agent-audit start"
echo "  4. View logs: sudo agent-audit log"
