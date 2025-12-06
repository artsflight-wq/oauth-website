#!/bin/bash
# YELL OAuth Server - Ubuntu Setup Script
# Run with: sudo bash setup.sh

set -e

echo ""
echo "============================================================"
echo "  YELL OAuth Server - Ubuntu + Cloudflare Setup"
echo "============================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo bash setup.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8080}"

echo "[1/7] Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

echo "[2/7] Installing Python dependencies..."
apt-get install -y -qq python3 python3-pip python3-venv curl wget

echo "[3/7] Installing Python packages..."
pip3 install --quiet --break-system-packages aiohttp motor uvloop

echo "[4/7] Configuring Cloudflare IP ranges for firewall..."
# Cloudflare IPv4 ranges
CLOUDFLARE_IPS=(
    "173.245.48.0/20"
    "103.21.244.0/22"
    "103.22.200.0/22"
    "103.31.4.0/22"
    "141.101.64.0/18"
    "108.162.192.0/18"
    "190.93.240.0/20"
    "188.114.96.0/20"
    "197.234.240.0/22"
    "198.41.128.0/17"
    "162.158.0.0/15"
    "104.16.0.0/13"
    "104.24.0.0/14"
    "172.64.0.0/13"
    "131.0.72.0/22"
)

# Allow Cloudflare IPs
for ip in "${CLOUDFLARE_IPS[@]}"; do
    iptables -C INPUT -s "$ip" -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -s "$ip" -p tcp --dport "$PORT" -j ACCEPT
done
echo "  ✓ Cloudflare IP ranges allowed on port $PORT"

# Allow localhost
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -A INPUT -i lo -j ACCEPT

# Save iptables rules
iptables-save > /etc/iptables.rules 2>/dev/null || true

echo "[5/7] Setting up file limits..."
cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 65535
* hard nofile 65535
EOF

echo "[6/7] Creating systemd service..."
cat > /etc/systemd/system/yell-oauth.service << EOF
[Unit]
Description=YELL OAuth Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/python3 $SCRIPT_DIR/service.py
Restart=always
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=60
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "  ✓ Systemd service created"

echo "[7/7] Verifying setup..."
python3 -c "import aiohttp, motor; print('  ✓ Python packages OK')"

echo ""
echo "============================================================"
echo "  Setup Complete!"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Set your Discord secrets in config.py or environment"
echo "  2. Start the service:  sudo systemctl start yell-oauth"
echo "  3. Enable auto-start:  sudo systemctl enable yell-oauth"
echo "  4. Check status:       sudo systemctl status yell-oauth"
echo "  5. View logs:          sudo journalctl -u yell-oauth -f"
echo ""
echo "Cloudflare configuration:"
echo "  - SSL/TLS: Full (strict)"
echo "  - Proxy status: Proxied (orange cloud)"
echo "  - Origin port: $PORT"
echo ""
