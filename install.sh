#!/bin/bash
set -e

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${1:-/usr/local/agent_audit}"
CONF_DIR="/etc/aa-edr"
LOG_DIR="/var/log/agent-audit"

if [ "$EUID" -ne 0 ]; then
    echo "Error: must run as root (sudo)"
    exit 1
fi

if [ "$INSTALL_DIR" = "$SRC_DIR" ]; then
    echo "Error: install directory cannot be the same as source directory"
    exit 1
fi

echo "Installing agent_audit to $INSTALL_DIR ..."

# Backup old config
BACKUP_CFG=""
if [ -f "$INSTALL_DIR/config.json" ]; then
    BACKUP_CFG=$(mktemp)
    cp "$INSTALL_DIR/config.json" "$BACKUP_CFG"
fi

# Install: clean old, copy new
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -r "$SRC_DIR"/* "$INSTALL_DIR/"

# Restore config or create default
if [ -n "$BACKUP_CFG" ]; then
    cp "$BACKUP_CFG" "$INSTALL_DIR/config.json"
    rm -f "$BACKUP_CFG"
    echo "Restored existing config"
elif [ ! -f "$INSTALL_DIR/config.json" ]; then
    cat > "$INSTALL_DIR/config.json" << 'EOF'
{
  "log": {
    "path": "/var/log/agent-audit/audit.log",
    "max_size_mb": 50,
    "backup_count": 5
  },
  "daemon": {
    "poll_interval_sec": 2,
    "bpf_elf": "ebpf/audit.bpf.o"
  },
  "targets": []
}
EOF
    chmod 600 "$INSTALL_DIR/config.json"
fi

# Create log dir
mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"

# Create symlink
ln -sf "$INSTALL_DIR/agent_audit" /usr/local/bin/agent_audit

# Record install path
mkdir -p "$CONF_DIR"
echo "$INSTALL_DIR" > "$CONF_DIR/agent.conf"
chmod 644 "$CONF_DIR/agent.conf"

# Remove source directory
rm -rf "$SRC_DIR"

echo ""
echo "Installation complete!"
echo "Install path: $INSTALL_DIR"
echo "Config path:  $INSTALL_DIR/config.json"
echo ""
echo "Start daemon: agent_audit daemon start"
