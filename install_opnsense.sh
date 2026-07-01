#!/bin/bash
set -e

# Default Configuration
HUB_URL="ws://localhost:8765"
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
    SPOKE_SECRET=""
    echo "ℹ️  No pre-shared secret — spoke will connect unauthenticated and await admin approval in the LM WebUI."
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
cd "$INSTALL_DIR"

if [ -d "opnsense" ]; then
    echo "📂 OPNsense directory exists. Preparing for update..."
    SPOKE_PATH="$INSTALL_DIR/opnsense"
    cd "$SPOKE_PATH"
    git pull
    cd "$INSTALL_DIR"
elif [ -d ".git" ]; then
    # This case is for when we are already inside the opnsense dir
    git pull
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
ExecStart=$INSTALL_DIR/opnsense/venv/bin/python3 -m src.control_plane --id \$SPOKE_ID --secret \$SPOKE_SECRET --hub \$HUB_URL --hub-secret \$HUB_SECRET
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
