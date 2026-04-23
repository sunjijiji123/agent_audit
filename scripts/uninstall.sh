#!/bin/bash
# Uninstall script for eBPF audit agent
# Stops daemon and removes installation, preserves logs

set -e

INSTALL_DIR="/usr/local/agent_audit"
CONFIG_DIR="/etc/agent_audit"
LOG_DIR="/var/log/agent-audit"
BIN_DIR="/usr/local/bin"
PID_FILE="/var/run/agent-audit.pid"

echo "=== Uninstalling eBPF Audit Agent ==="
echo ""

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (use sudo)"
    exit 1
fi

# Stop daemon if running
echo "Checking for running daemon..."
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping daemon (PID $PID)..."
        kill "$PID"
        sleep 2
        if kill -0 "$PID" 2>/dev/null 2>&1; then
            echo "WARNING: Daemon still running, forcing kill..."
            kill -9 "$PID"
        fi
    fi
    rm -f "$PID_FILE"
fi

# Remove executable wrapper
echo "Removing executable wrapper..."
rm -f "$BIN_DIR/agent-audit"

# Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo "Removing installation directory: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
fi

# Ask about configuration
echo ""
read -p "Remove configuration directory $CONFIG_DIR? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing configuration..."
    rm -rf "$CONFIG_DIR"
else
    echo "Keeping configuration at $CONFIG_DIR"
fi

# Logs are preserved by default
echo ""
echo "Log directory preserved: $LOG_DIR"
echo "  To remove logs: sudo rm -rf $LOG_DIR"

echo ""
echo "=== Uninstallation Complete ==="
