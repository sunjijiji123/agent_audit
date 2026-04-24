#!/bin/bash
set -e

CONF_FILE="/etc/aa-edr/agent.conf"

if [ "$EUID" -ne 0 ]; then
    echo "Error: must run as root (sudo)"
    exit 1
fi

# Read install path from config
if [ -f "$CONF_FILE" ]; then
    INSTALL_DIR=$(cat "$CONF_FILE")
else
    echo "Error: $CONF_FILE not found."
    echo "If installed elsewhere, specify path:"
    echo "  sudo ./uninstall.sh /your/custom/path"
    exit 1
fi

if [ ! -d "$INSTALL_DIR" ]; then
    echo "Install directory not found: $INSTALL_DIR"
    exit 1
fi

echo "Removing $INSTALL_DIR ..."

# Stop daemon
PID_FILE="/tmp/agent-audit-daemon.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE" 2>/dev/null || true)
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        echo "Stopping daemon (PID $PID)..."
        kill "$PID" 2>/dev/null || true
        sleep 1
    fi
    rm -f "$PID_FILE"
fi

# Remove install dir, symlink, and config record
rm -rf "$INSTALL_DIR"
rm -f /usr/local/bin/agent_audit
rm -f "$CONF_FILE"

echo "Uninstalled."
echo "Note: audit logs in /var/log/agent-audit/ were NOT removed."
