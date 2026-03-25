#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Run as root: sudo bash setup_nginx_host.sh [domain]"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
HOST_IP="$(hostname -I | awk '{print $1}')"
if [[ -z "$HOST_IP" ]]; then
  HOST_IP="127.0.0.1"
fi
DOMAIN="${1:-$HOST_IP}"
SERVICE_NAME="soc-ip-dashboard"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
NGINX_SITE="/etc/nginx/sites-available/${SERVICE_NAME}"

VENV_PYTHON="$ROOT_DIR/venv/bin/python"
APP_PATH="$ROOT_DIR/soc_ip_governance/app.py"

if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "[ERROR] Python venv not found at: $VENV_PYTHON"
  echo "Create it first: python3 -m venv venv && source venv/bin/activate"
  exit 1
fi

if [[ ! -f "$APP_PATH" ]]; then
  echo "[ERROR] Streamlit app not found: $APP_PATH"
  exit 1
fi

echo "[1/5] Installing nginx (if missing)..."
apt-get update -y
apt-get install -y nginx

echo "[2/5] Writing systemd service: ${SERVICE_NAME}"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SOC IP Dashboard Streamlit Service
After=network.target

[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${ROOT_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=${VENV_PYTHON} -m streamlit run ${APP_PATH} --server.port 8501 --server.address 127.0.0.1 --server.headless true
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "[3/5] Writing nginx reverse proxy site..."
cat > "$NGINX_SITE" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
EOF

ln -sf "$NGINX_SITE" "/etc/nginx/sites-enabled/${SERVICE_NAME}"
rm -f /etc/nginx/sites-enabled/default

echo "[4/5] Enabling services..."
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo "[5/5] Validating and reloading nginx..."
nginx -t
systemctl enable nginx
systemctl restart nginx

echo ""
echo "✅ Setup complete"
echo "- Streamlit service: ${SERVICE_NAME}"
echo "- Nginx site: ${NGINX_SITE}"
echo "- Host IP: ${HOST_IP}"
echo "- Open: http://${DOMAIN}"
echo "- Local: http://localhost"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status ${SERVICE_NAME}"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo "  sudo systemctl restart ${SERVICE_NAME} nginx"
