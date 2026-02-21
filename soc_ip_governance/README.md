# SOC IP Governance Automation

Python + Streamlit based passive SOC workflow for IP governance and documentation.

## Features

- Loads **Master Blocking Sheet** CSV and treats it as authoritative blocked IP list
- Parses multiline raw input and validates via regex (`IPv4` + `IPv6`)
- Removes invalid lines and duplicate IPs
- Filters out already blocked IPs from master sheet
- Enriches new IPs through AbuseIPDB API v2 `/check`
- Applies configurable threat threshold (default `8`)
- Persists detected threats in SQLite
- Supports approval workflow and auto-appends approved IPs to master CSV

## Project Structure

```text
soc_ip_governance/
├── app.py
├── abuseipdb.py
├── ip_validator.py
├── master_sheet.py
├── database.py
├── config.py
├── requirements.txt
└── README.md
```

## Setup

1. Open terminal in this folder:
   ```bash
   cd /home/prathameshpendkar/Desktop/soc_ip_dashboard/soc_ip_governance
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set API key (required) in config file (recommended):
   - Open [config.ini](config.ini)
   - Set:
   ```ini
   [abuseipdb]
   api_key = your_api_key_here
   ```
4. Alternative: set API key in environment:
   ```bash
   export ABUSEIPDB_API_KEY="your_api_key_here"
   ```
5. (Optional) Override defaults:
   ```bash
   export MASTER_BLOCK_SHEET="/home/prathameshpendkar/Desktop/soc_ip_dashboard/IP Blocking - Sheet6.csv"
   export ABUSEIPDB_THRESHOLD="8"
   export SOC_APPROVER_NAME="Prathamesh"
   ```
6. Run dashboard:
   ```bash
   streamlit run app.py
   ```

## Master Sheet Row Format

Rows are appended in strict format:

```text
YYYY-MM-DD,[Name],[IP Address],"Malicious Activity",HH:MM AM/PM,,[Notes],,
```

## Required Core Functions Implemented

- `is_valid_ipv4()`
- `is_valid_ipv6()`
- `extract_valid_ips()`
- `remove_duplicates()`
- `load_master_blocked_ips()`
- `filter_already_blocked()`
- `query_abuseipdb()`
- `append_to_master_sheet()`
- `generate_summary_stats()`

## Security & Reliability Notes

- API key is loaded from `config.ini` or environment, not hardcoded in UI
- Request retries with rate-limit handling (`HTTP 429`)
- Exception handling and logging enabled across modules
- Input lines sanitized and trimmed before validation
- Duplicate insertion into master CSV is prevented

## Mode

Passive SOC mode only. No automated firewall or Cloudflare actions.
