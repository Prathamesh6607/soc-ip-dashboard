# Cloudflare Logpush SOAR Module Guide

## Overview
The SOAR (Security Orchestration, Automation and Response) module continuously monitors Cloudflare Logpush HTTP request logs and automatically blocks malicious IPs via the Cloudflare API.

**🔄 Integration:** SOAR detections appear directly in the **Detected Threats** tab alongside AbuseIPDB results, creating a unified threat management view.

## Quick Start

### 1. Set Environment Variables
```bash
export CLOUDFLARE_API_TOKEN='your-cloudflare-api-token'
export ZONE_ID='your-cloudflare-zone-id'
export LOG_INPUT_PATH='/home/prathameshpendkar/Desktop/soc_ip_dashboard/logpush_simulation.json'
```

### 2. Run via Dashboard (Recommended)
1. Start the dashboard: `./run_dashboard.sh`
2. Navigate to the **Cloudflare SOAR** tab
3. Click **▶ Start SOAR**
4. Monitor the runtime output and decision log in real-time

### 3. Run Standalone
```bash
cd /home/prathameshpendkar/Desktop/soc_ip_dashboard
source venv/bin/activate
python soc_ip_governance/cloudflare_soar_module.py
```

## Detection Logic

### High Volume Attack
- **Threshold:** More than 20 requests from one IP in 60 seconds
- **Action:** Flag as suspicious and block

### Sensitive Path Abuse
- **Paths:** `/wp-login.php`, `/admin`, `/login`, `/.env`
- **Threshold:** More than 5 hits to sensitive paths in 60 seconds
- **Action:** Mark as malicious and block

### Scanner Behavior
- **Threshold:** More than 10 unique paths from one IP in 60 seconds
- **Action:** Mark as scanner and block

## Configuration

All settings can be configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDFLARE_API_TOKEN` | *required* | Cloudflare API token with firewall write access |
| `ZONE_ID` | *required* | Cloudflare Zone ID |
| `LOG_INPUT_PATH` | `./logs` | Path to log file or directory |
| `SCAN_INTERVAL_SECONDS` | `60` | Processing interval in seconds |
| `REQUEST_THRESHOLD` | `20` | Max requests before flagging as high volume |
| `SENSITIVE_PATH_THRESHOLD` | `5` | Max sensitive path hits before blocking |
| `UNIQUE_PATH_THRESHOLD` | `10` | Max unique paths before flagging as scanner |
| `AUTO_UNBLOCK_HOURS` | `24` | Hours before automatic unblock |
| `DECISION_LOG_FILE` | `soar_decisions.log` | Decision log output path |
| `BLOCKED_STATE_FILE` | `blocked_state.json` | Persistent blocked IP state |

## Log Format

The module expects newline-delimited JSON with these fields:

```json
{
  "ClientIP": "192.0.2.1",
  "ClientRequestURI": "/admin",
  "ClientRequestHost": "api.company.com",
  "EdgeResponseStatus": 403,
  "WAFAction": "log",
  "EdgeStartTimestamp": 1772021844585318
}
```

## Output Files

- **soar_decisions.log** - All detection decisions with timestamps and reasons
- **soar_runtime.log** - Runtime output (stdout/stderr)
- **blocked_state.json** - Persistent state of blocked IPs with rule IDs
- **.soar_module.pid** - Process ID file for dashboard control

## Sample Data

Use the included `logpush_simulation.json` for testing:
- **100,000+** simulated Cloudflare log entries
- Contains realistic attack patterns for detection testing
- Pre-loaded in the workspace root

## How It Works

1. **Parse Logs:** Reads newline-delimited JSON from configured path
2. **Track Activity:** Maintains rolling 60-second window per IP
3. **Detect Threats:** Applies detection rules in real-time
4. **Block via API:** Calls Cloudflare API to create firewall rules
5. **Auto-Unblock:** Removes blocks after 24 hours (configurable)
6. **Persist State:** Saves blocked IPs to survive restarts

## Monitoring

### Dashboard Tab
- Real-time status (Running/Stopped)
- Log analysis preview with threat metrics
- Recent decision log preview
- Runtime output streaming

### Log Files
```bash
# Watch decision log
tail -f soar_decisions.log

# Watch runtime output
tail -f soar_runtime.log
```

## Stopping the Module

### Via Dashboard
1. Navigate to **Cloudflare SOAR** tab
2. Click **■ Stop SOAR**

### Via Terminal
```bash
# Find PID
cat soc_ip_governance/.soar_module.pid

# Kill process
kill $(cat soc_ip_governance/.soar_module.pid)
```

## Production Deployment

1. **Get Cloudflare API Token:**
   - Go to Cloudflare Dashboard → My Profile → API Tokens
   - Create token with `Zone.Firewall Services` edit permission

2. **Get Zone ID:**
   - Cloudflare Dashboard → Select Domain → Overview
   - Copy Zone ID from right sidebar

3. **Configure Log Source:**
   - Set up Cloudflare Logpush to write to local file or directory
   - Update `LOG_INPUT_PATH` environment variable

4. **Run as Service:**
   - Use systemd, supervisor, or process manager
   - Ensure environment variables are set
   - Monitor `soar_decisions.log` for activity

## Troubleshooting

### No detections
- Check `LOG_INPUT_PATH` is correct
- Verify log format matches expected schema
- Increase log sample size or wait for more traffic

### API errors
- Verify `CLOUDFLARE_API_TOKEN` has correct permissions
- Check `ZONE_ID` matches your domain zone
- Review `soar_runtime.log` for detailed error messages

### Process won't start
- Check environment variables are set
- Verify Python dependencies are installed
- Review file permissions for log output paths

## Architecture

```
┌─────────────────┐
│  Logpush File   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  SOAR Parser    │────▶│  IP Tracker      │
└─────────────────┘     │  (Rolling Window)│
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ Detection Engine │
                        │  • High volume   │
                        │  • Sensitive     │
                        │  • Scanner       │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │  Cloudflare API  │
                        │  Block/Unblock   │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │  Decision Log    │
                        │  State File      │
                        └──────────────────┘
```

## Integration with Main Dashboard

The SOAR module is fully integrated into the SOC IP Governance dashboard:

### Unified Threat View
- **SOAR detections appear in "Detected Threats" tab** with 🔍 SOAR icon
- **AbuseIPDB results shown with** 🌐 AbuseIPDB icon
- Both sources use the same approval workflow
- Metrics show breakdown: Total | AbuseIPDB | SOAR

### Detection Format
SOAR detections are stored with these fields:
- **IP Address:** Detected malicious IP
- **Abuse Score:** Request count (how many requests triggered detection)
- **Country Code:** `SOAR` (marker for SOAR detections)
- **ISP:** Detection reason (`SOAR:high_request_rate`, `SOAR:sensitive_path_abuse`, `SOAR:scanner_behavior`)
- **PATH:** Detailed description
- **Approval Status:** Pending/Approved/Rejected (editable inline)

### Workflow Integration
1. SOAR detects malicious IP in logpush data
2. IP automatically added to **Detected Threats** tab
3. Review detection in same table as AbuseIPDB results
4. Approve/reject using inline editor
5. Bulk send approved IPs to master blocking sheet
6. Email notifications work for both SOAR and AbuseIPDB threats

---

**Note:** This is a fallback/supplementary mechanism to the main AbuseIPDB-based workflow. Use it for proactive Cloudflare log monitoring when you have access to Logpush data.
