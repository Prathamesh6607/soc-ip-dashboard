#!/bin/bash
# Quick test script for SOAR module in demo mode

echo "==================================================================="
echo "Starting SOAR module in DEMO MODE (no actual blocking)"
echo "==================================================================="
echo ""
echo "Press Ctrl+C to stop the module"
echo ""

cd "$(dirname "$0")"

export DEMO_MODE=1
export LOG_INPUT_PATH="$(pwd)/logpush_simulation.json"
export SQLITE_DB_PATH="$(pwd)/soc_ip_governance.db"
export SCAN_INTERVAL_SECONDS=10
export REQUEST_THRESHOLD=20
export SENSITIVE_PATH_THRESHOLD=5
export UNIQUE_PATH_THRESHOLD=10

echo "Configuration:"
echo "  - Log file: $LOG_INPUT_PATH"
echo "  - Database: $SQLITE_DB_PATH"
echo "  - Scan interval: ${SCAN_INTERVAL_SECONDS}s"
echo "  - Demo mode: YES (no actual blocking)"
echo ""
echo "Malicious IPs will appear in 'Detected Threats' tab"
echo ""

source venv/bin/activate
python soc_ip_governance/cloudflare_soar_module.py
