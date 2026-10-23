#!/bin/bash
# Zscaler POV Kit: the POV test app on a CloudShare (or any) Linux machine: one page on port 80, the app ZPA
# protects when the customer hasn't named one (pov-app.zpov.internal). Run once when building the blueprint; it
# starts on every boot. Nothing customer-specific is in it.
#
#   curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zpov-test-app.sh | sudo bash
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run it with sudo."; exit 1; }
command -v python3 >/dev/null || dnf -y -q install python3 || apt-get install -y -qq python3
mkdir -p /srv/pov-app
cat > /srv/pov-app/index.html <<'ZPOV_PAGE'
<!doctype html><title>Zscaler POV test app</title><h1>Zscaler POV test app</h1>
<p>You reached this private page through Zscaler Private Access.</p>
ZPOV_PAGE
cat > /etc/systemd/system/pov-app.service <<'ZPOV_UNIT'
[Unit]
Description=Zscaler POV test app
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 80 --directory /srv/pov-app
Restart=always
[Install]
WantedBy=multi-user.target
ZPOV_UNIT
systemctl daemon-reload
systemctl enable --now pov-app
command -v firewall-cmd >/dev/null && firewall-cmd -q --permanent --add-port=80/tcp && firewall-cmd -q --reload || true
IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
echo "  The POV test app is running. Its address: ${IP:-see 'ip addr'}"
echo "  Give this address to each connector: zpov-connector.sh enroll <key> ${IP:-<address>}"
