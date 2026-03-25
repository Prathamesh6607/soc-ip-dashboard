#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="soc-ip-dashboard"
HOST_IP="$(hostname -I | awk '{print $1}')"
if [[ -z "$HOST_IP" ]]; then
	HOST_IP="127.0.0.1"
fi

echo "Restarting dashboard service and nginx..."
sudo systemctl daemon-reload
sudo systemctl restart "$SERVICE_NAME"
sudo systemctl restart nginx

echo ""
echo "Service status:"
sudo systemctl --no-pager --full status "$SERVICE_NAME" | sed -n '1,12p'

echo ""
echo "✅ Dashboard is now hosted through Nginx."
echo "Open (this machine): http://localhost"
echo "Open (LAN): http://${HOST_IP}"
