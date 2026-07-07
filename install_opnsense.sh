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

# Accept a bare hub IP/host for --hub (e.g. `--hub 172.16.1.31` == `--hub
# wss://172.16.1.31:443`). A ws://|wss:// scheme or the "auto" sentinel is left
# as-is; host:port gets a scheme; a bare host defaults to the unified :443.
if [ -n "${HUB_URL:-}" ] && [ "$HUB_URL" != "auto" ]; then
    case "$HUB_URL" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       HUB_URL="wss://${HUB_URL}" ;;
        *)              HUB_URL="wss://${HUB_URL}:443" ;;
    esac
fi

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

# The git clone/reset above ran as root; the spoke runs as svc_lm and
# self-updates via `git reset --hard`/`git pull` as that user — root-owned
# .git/objects → "insufficient permission for adding an object" → self-update
# fails. Hand the repo to svc_lm + trust the dir (mirrors cs/netbox installers).
chown -R svc_lm:svc_lm "$SPOKE_PATH" 2>/dev/null || true
runuser -u svc_lm -- git config --global --add safe.directory "$SPOKE_PATH" 2>/dev/null || true

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
# Preserve the minted INSTALL_UUID across a re-run so the hub-side fingerprint
# (install_uuid) stays stable. The cat > below truncates .env, so without this
# the UUID line is wiped and the spoke mints a fresh one on next start → hub
# records a `reimaged` (fingerprint-changed) event for a box that was only
# updated. _ensure_install_uuid mints on first start only when this line is
# absent, so a fresh install is unchanged.
INSTALL_UUID_LINE=""
if [ -f .env ] && grep -q "^INSTALL_UUID=" .env; then
    EXISTING_UUID=$(grep "^INSTALL_UUID=" .env | cut -d= -f2-)
    [ -n "$EXISTING_UUID" ] && INSTALL_UUID_LINE="INSTALL_UUID=$EXISTING_UUID" \
        && echo "Preserving existing install UUID (hub fingerprint)."
fi
cat <<EOF > .env
HUB_URL=$HUB_URL
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_SECRET=$HUB_SECRET
${INSTALL_UUID_LINE}
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
# Start it now (and pick up new code on a re-install). enable alone left the unit
# inactive until the next reboot, so the spoke never connected to --hub.
systemctl restart lm-opnsense

echo "🎉 OPNsense Manager installation complete!"
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"
