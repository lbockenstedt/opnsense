#!/bin/bash
set -e

# Default Configuration
# HUB_URL defaults to "auto": the spoke auto-discovers the hub (DNS
# lm-hub.<suffix> then mDNS) on each connect via BaseControlPlane. The old
# "ws://localhost:8765" default is BROKEN now that the hub's bare 8765 listener
# was retired by the unified-:443 merge (the hub serves only on :443); a
# co-located spoke dialed a dead port and a remote one dialed its own localhost.
# Pass --hub <url> to pin.
HUB_URL="${HUB_URL:-auto}"
SPOKE_ID="${SPOKE_ID:-opn-$(hostname -s)}"
SPOKE_SECRET="lm-secret"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        --all-prereqs) ;;  # no-op; accepted for LM hub compat
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "lm-secret" ]; then
    # Keep the default PSK "lm-secret" (do NOT clear to "") so the =-attached
    # ExecStart below (--secret=$SPOKE_SECRET) resolves to "lm-secret" at
    # runtime — matching the prior bare `--secret` argparse const="lm-secret"
    # zero-touch behavior. Clearing to "" would make `--secret=` pass an empty
    # string (pending negotiation) instead of the default-PSK path.
    SPOKE_SECRET="lm-secret"
    echo "ℹ️  No pre-shared secret — spoke will connect with the default PSK 'lm-secret' (zero-touch; the hub auto-approves the default PSK or awaits admin approval in the LM WebUI)."
fi

echo "🚀 Installing OPNsense Manager Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git curl

INSTALL_DIR="/opt/lm"
OLD_INSTALL_DIR="/opt/lm-manager"

# Cleanup legacy installation
if [ -d "$OLD_INSTALL_DIR" ]; then
    echo "🗑️  Removing legacy installation at $OLD_INSTALL_DIR..."
    rm -rf "$OLD_INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR"
mkdir -p /var/log/lm   # systemd `append:` won't create the parent dir → unit 206/EXEC on a clean box

# Circular logging: cap /var/log/lm/*.log so it can't fill the disk (copytruncate
# keeps the inode → the running spoke's O_APPEND FileHandler + systemd stderr
# keep appending). Belt-and-suspenders alongside logging_setup's RotatingFileHandler.
cat > /etc/logrotate.d/lm <<'LOGROTATE'
/var/log/lm/*.log /var/log/client-sim-*.log {
    su root root
    size 50M
    rotate 5
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LOGROTATE

cd "$INSTALL_DIR"

if [ -d "opnsense" ]; then
    echo "📂 OPNsense directory exists. Preparing for update..."
    SPOKE_PATH="$INSTALL_DIR/opnsense"
    cd "$SPOKE_PATH"
    git fetch origin -q && git reset --hard origin/main   # hard-sync (soft `git pull` no-ops on a diverged/detached clone)
    cd "$INSTALL_DIR"
elif [ -d ".git" ]; then
    # This case is for when we are already inside the opnsense dir
    git fetch origin -q && git reset --hard origin/main   # hard-sync
    SPOKE_PATH="$(pwd)"
else
    echo "🌐 Cloning OPNsense Manager repository..."
    git clone https://github.com/lbockenstedt/opnsense.git
    SPOKE_PATH="$INSTALL_DIR/opnsense"
fi

echo "🛠️ Setting up OPNsense Manager..."
cd "$SPOKE_PATH"

# Always remove existing venv to ensure clean local environment (prevents cross-platform path issues)
echo "♻️ Resetting virtual environment..."
rm -rf venv

python3 -m venv venv
if [ ! -f "venv/bin/python3" ]; then
    echo "❌ Critical Error: venv creation failed."
    exit 1
fi

echo "Installing requirements..."
./venv/bin/python3 -m pip install --upgrade pip -q
if [ -f "requirements.txt" ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt -q
fi

# --- Persistence Configuration ---
echo "⚙️ Configuring Spoke Identity..."
cat <<EOF > .env
HUB_URL=$HUB_URL
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_SECRET=$HUB_SECRET
EOF

# --- Systemd Service (For Remote/Independent Deployment) ---
echo "⚙️ Creating systemd service for auto-start..."
cat <<EOF > /etc/systemd/system/lm-opnsense.service
[Unit]
Description=Lab Manager Spoke - OPNsense Manager
After=network.target

[Service]
Type=simple
User=svc_lm
WorkingDirectory=$INSTALL_DIR/opnsense
EnvironmentFile=$INSTALL_DIR/opnsense/.env
Environment="PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/opnsense/src"
ExecStart=$INSTALL_DIR/opnsense/venv/bin/python3 -m src.control_plane --id "\$SPOKE_ID" --secret=\$SPOKE_SECRET --hub "\$HUB_URL" --hub-secret="\$HUB_SECRET"
StandardOutput=append:/var/log/lm/lm-opnsense.log
StandardError=append:/var/log/lm/lm-opnsense.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-opnsense

echo "🎉 OPNsense Manager installation complete!"
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"
