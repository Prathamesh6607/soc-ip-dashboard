#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$ROOT_DIR/venv/bin/python"
APP_PATH="$ROOT_DIR/soc_ip_governance/app.py"
NGROK_SCRIPT="$ROOT_DIR/soc_ip_governance/ngrok_tunnel.py"
NGROK_TOKEN_FILE="$ROOT_DIR/.ngrok_token"
PORT="8501"

if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "[ERROR] Python venv not found at: $VENV_PYTHON"
  echo "Create it first: python3 -m venv venv && source venv/bin/activate"
  exit 1
fi

if [[ ! -f "$APP_PATH" ]]; then
  echo "[ERROR] Streamlit app not found: $APP_PATH"
  exit 1
fi

if [[ ! -f "$NGROK_SCRIPT" ]]; then
  echo "[ERROR] ngrok launcher not found: $NGROK_SCRIPT"
  exit 1
fi

cleanup() {
  if [[ -n "${STREAMLIT_PID:-}" ]] && kill -0 "$STREAMLIT_PID" 2>/dev/null; then
    echo ""
    echo "Stopping Streamlit (PID: $STREAMLIT_PID)..."
    kill "$STREAMLIT_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Kill any existing Streamlit processes on port 8501
echo "Checking for existing Streamlit processes..."
if lsof -ti:$PORT >/dev/null 2>&1; then
  echo "Port $PORT is in use. Stopping existing processes..."
  pkill -9 -f "streamlit.*8501" 2>/dev/null || true
  lsof -ti:$PORT | xargs kill -9 2>/dev/null || true
  sleep 2
fi

echo "Starting Streamlit on port $PORT..."
"$VENV_PYTHON" -m streamlit run "$APP_PATH" \
  --server.port "$PORT" \
  --server.headless true \
  --server.enableCORS false \
  --server.enableXsrfProtection false \
  > "$ROOT_DIR/.streamlit_launch.log" 2>&1 &
STREAMLIT_PID=$!

sleep 3
if ! kill -0 "$STREAMLIT_PID" 2>/dev/null; then
  echo "[ERROR] Streamlit failed to start. Check log: $ROOT_DIR/.streamlit_launch.log"
  exit 1
fi

echo "Streamlit started (PID: $STREAMLIT_PID)"
echo "Local URL: http://localhost:$PORT"
echo ""

NGROK_AUTHTOKEN_VALUE="${NGROK_AUTHTOKEN:-}"
if [[ -z "$NGROK_AUTHTOKEN_VALUE" && -f "$NGROK_TOKEN_FILE" ]]; then
  NGROK_AUTHTOKEN_VALUE="$(tr -d ' \t\r\n' < "$NGROK_TOKEN_FILE")"
fi

if [[ -n "$NGROK_AUTHTOKEN_VALUE" ]]; then
  echo "Configuring ngrok authtoken..."
  NGROK_AUTHTOKEN="$NGROK_AUTHTOKEN_VALUE" "$VENV_PYTHON" -c "import os; from pyngrok import ngrok; ngrok.set_auth_token(os.environ['NGROK_AUTHTOKEN'])"
else
  echo "[WARNING] ngrok token not found. Set NGROK_AUTHTOKEN env var or create $NGROK_TOKEN_FILE"
fi

echo "Resetting old ngrok sessions (if any)..."
"$VENV_PYTHON" -c "from pyngrok import ngrok; ngrok.kill()" >/dev/null 2>&1 || true

echo "Starting ngrok tunnel (Ctrl+C to stop both ngrok and Streamlit)..."
if ! "$VENV_PYTHON" "$NGROK_SCRIPT"; then
  echo ""
  echo "[WARNING] ngrok tunnel did not start."
  echo "Streamlit is still running locally at: http://localhost:$PORT"
  echo ""
  echo "Fix: open https://dashboard.ngrok.com/ and stop old active endpoints/agents, then rerun ./run_dashboard.sh"
  echo "Press Ctrl+C to stop local Streamlit."
  wait "$STREAMLIT_PID"
fi
