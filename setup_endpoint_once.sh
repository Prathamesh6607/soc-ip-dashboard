#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Run as root: sudo bash setup_endpoint_once.sh [options]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR}"
APP_USER="${APP_USER:-${SUDO_USER:-$(logname 2>/dev/null || echo root)}}"
SERVICE_NAME="soc-ip-dashboard"
NGROK_SERVICE_NAME="soc-ip-dashboard-ngrok"

HOST_IP="$(hostname -I | awk '{print $1}')"
if [[ -z "$HOST_IP" ]]; then
  HOST_IP="127.0.0.1"
fi

DOMAIN="${DOMAIN:-$HOST_IP}"
ENABLE_NGROK="${ENABLE_NGROK:-false}"
NGROK_STATIC_DOMAIN="${NGROK_STATIC_DOMAIN:-}"
NGROK_AUTHTOKEN="${NGROK_AUTHTOKEN:-}"

usage() {
  cat <<'EOF'
Usage:
  sudo bash setup_endpoint_once.sh [options]

Options:
  --project-dir <path>       Project root path (default: script directory)
  --user <linux-user>        Linux user to run services (default: sudo user)
  --domain <host/domain>     Nginx server_name (default: first host IP)
  --enable-ngrok             Enable static ngrok service
  --ngrok-domain <domain>    Reserved static ngrok domain
  --ngrok-token <token>      ngrok authtoken to configure for service user
  --help                     Show this help

Examples:
  sudo bash setup_endpoint_once.sh --domain 192.168.1.9
  sudo bash setup_endpoint_once.sh --enable-ngrok --ngrok-domain your-static.ngrok-free.dev --ngrok-token <TOKEN>
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-dir)
      PROJECT_DIR="$2"
      shift 2
      ;;
    --user)
      APP_USER="$2"
      shift 2
      ;;
    --domain)
      DOMAIN="$2"
      shift 2
      ;;
    --enable-ngrok)
      ENABLE_NGROK="true"
      shift
      ;;
    --ngrok-domain)
      NGROK_STATIC_DOMAIN="$2"
      shift 2
      ;;
    --ngrok-token)
      NGROK_AUTHTOKEN="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "[ERROR] Project directory not found: $PROJECT_DIR"
  exit 1
fi

APP_PATH="$PROJECT_DIR/soc_ip_governance/app.py"
REQ_FILE="$PROJECT_DIR/soc_ip_governance/requirements.txt"
VENV_DIR="$PROJECT_DIR/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
NGINX_SITE="/etc/nginx/sites-available/${SERVICE_NAME}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
NGROK_SERVICE_FILE="/etc/systemd/system/${NGROK_SERVICE_NAME}.service"

if [[ ! -f "$APP_PATH" ]]; then
  echo "[ERROR] Streamlit app not found: $APP_PATH"
  exit 1
fi

if [[ ! -f "$REQ_FILE" ]]; then
  echo "[ERROR] requirements.txt not found: $REQ_FILE"
  exit 1
fi

echo "[1/7] Installing required apt packages..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip nginx

echo "[2/7] Creating/updating Python virtual environment..."
if [[ ! -x "$VENV_PYTHON" ]]; then
  sudo -u "$APP_USER" python3 -m venv "$VENV_DIR"
fi
sudo -u "$APP_USER" "$VENV_PYTHON" -m pip install --upgrade pip
sudo -u "$APP_USER" "$VENV_PYTHON" -m pip install -r "$REQ_FILE"

echo "[3/7] Writing systemd service: ${SERVICE_NAME}"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SOC IP Dashboard Streamlit Service
After=network.target

[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${PROJECT_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=${VENV_PYTHON} -m streamlit run ${APP_PATH} --server.port 8501 --server.address 127.0.0.1 --server.headless true
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "[4/7] Writing nginx reverse-proxy site..."
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

echo "[5/7] Enabling and starting dashboard + nginx..."
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
nginx -t
systemctl enable nginx
systemctl restart nginx

if [[ "$ENABLE_NGROK" == "true" ]]; then
  if [[ -z "$NGROK_STATIC_DOMAIN" ]]; then
    echo "[ERROR] --enable-ngrok requires --ngrok-domain"
    exit 1
  fi

  NGROK_BIN="$(command -v ngrok || true)"
  if [[ -z "$NGROK_BIN" ]]; then
    echo "[ERROR] ngrok not found in PATH. Install ngrok first."
    exit 1
  fi

  echo "[6/7] Configuring ngrok service..."
  if [[ -n "$NGROK_AUTHTOKEN" ]]; then
    sudo -u "$APP_USER" "$NGROK_BIN" config add-authtoken "$NGROK_AUTHTOKEN"
  fi

  APP_HOME="$(eval echo "~$APP_USER")"
  cat > "$NGROK_SERVICE_FILE" <<EOF
[Unit]
Description=SOC IP Dashboard ngrok Tunnel
After=network-online.target nginx.service ${SERVICE_NAME}.service
Wants=network-online.target nginx.service ${SERVICE_NAME}.service

[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${PROJECT_DIR}
Environment=HOME=${APP_HOME}
ExecStart=${NGROK_BIN} http --url=${NGROK_STATIC_DOMAIN} 80 --log=stdout
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$NGROK_SERVICE_NAME"
else
  echo "[6/7] ngrok setup skipped."
fi

echo "[7/7] Final service status check..."
systemctl --no-pager --full status "$SERVICE_NAME" | sed -n '1,12p'
systemctl --no-pager --full status nginx | sed -n '1,12p'
if [[ "$ENABLE_NGROK" == "true" ]]; then
  systemctl --no-pager --full status "$NGROK_SERVICE_NAME" | sed -n '1,12p'
fi

echo ""
echo "✅ One-time endpoint setup complete"
echo "- App service: ${SERVICE_NAME}"
echo "- Nginx URL: http://${DOMAIN}"
echo "- Local URL: http://localhost"
if [[ "$ENABLE_NGROK" == "true" ]]; then
  echo "- Public URL: https://${NGROK_STATIC_DOMAIN}"
fi
