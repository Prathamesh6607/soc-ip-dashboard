from __future__ import annotations

import csv
import json
import logging
import os
import sqlite3
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import AddressValueError, ip_address, ip_network
from pathlib import Path
from typing import Any

import requests

# Import AbuseIPDB query function
try:
    from abuseipdb import query_abuseipdb
except ImportError:
    query_abuseipdb = None


@dataclass
class AppConfig:
    cloudflare_api_token: str
    zone_id: str
    log_input_path: Path
    log_glob: str = "*.json*"
    scan_interval_seconds: int = 60
    request_threshold: int = 20
    sensitive_path_threshold: int = 5
    unique_path_threshold: int = 10
    sensitive_paths: set[str] = field(default_factory=lambda: {"/wp-login.php", "/admin", "/login", "/.env"})
    decision_log_file: Path = Path("soar_decisions.log")
    state_file: Path = Path("blocked_state.json")
    sqlite_db_path: Path = Path("soc_ip_governance.db")
    master_sheet_path: Path = Path("IP Blocking - Sheet6.csv")
    whitelist_path: Path = Path("ip_not_blocked.csv")
    request_timeout_seconds: int = 15
    auto_unblock_hours: int = 24
    abuseipdb_api_key: str = ""
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"
    abuseipdb_timeout: int = 15
    abuseipdb_max_retries: int = 3
    abuseipdb_backoff: float = 1.5

    @staticmethod
    def from_env() -> "AppConfig":
        token = os.getenv("CLOUDFLARE_API_TOKEN", "").strip()
        zone_id = os.getenv("ZONE_ID", "").strip()
        log_input_path = Path(os.getenv("LOG_INPUT_PATH", "./logs")).expanduser().resolve()
        sensitive_paths_raw = os.getenv("SENSITIVE_PATHS", "/wp-login.php,/admin,/login,/.env")
        sensitive_paths = {part.strip() for part in sensitive_paths_raw.split(",") if part.strip()}
        sqlite_db = Path(os.getenv("SQLITE_DB_PATH", "soc_ip_governance.db")).expanduser().resolve()
        
        # Get project root (parent of soc_ip_governance/) for CSV files
        project_root = sqlite_db.parent.parent if sqlite_db.parent.name == "soc_ip_governance" else sqlite_db.parent
        master_sheet = Path(os.getenv("MASTER_BLOCK_SHEET", str(project_root / "IP Blocking - Sheet6.csv"))).expanduser().resolve()
        whitelist = Path(os.getenv("WHITELIST_SHEET", str(project_root / "ip_not_blocked.csv"))).expanduser().resolve()

        return AppConfig(
            cloudflare_api_token=token,
            zone_id=zone_id,
            log_input_path=log_input_path,
            log_glob=os.getenv("LOG_GLOB", "*.json*"),
            scan_interval_seconds=int(os.getenv("SCAN_INTERVAL_SECONDS", "60")),
            request_threshold=int(os.getenv("REQUEST_THRESHOLD", "20")),
            sensitive_path_threshold=int(os.getenv("SENSITIVE_PATH_THRESHOLD", "5")),
            unique_path_threshold=int(os.getenv("UNIQUE_PATH_THRESHOLD", "10")),
            sensitive_paths=sensitive_paths,
            decision_log_file=Path(os.getenv("DECISION_LOG_FILE", "soar_decisions.log")).expanduser().resolve(),
            state_file=Path(os.getenv("BLOCKED_STATE_FILE", "blocked_state.json")).expanduser().resolve(),
            sqlite_db_path=sqlite_db,
            master_sheet_path=master_sheet,
            whitelist_path=whitelist,
            request_timeout_seconds=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "15")),
            auto_unblock_hours=int(os.getenv("AUTO_UNBLOCK_HOURS", "24")),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip(),
            abuseipdb_url=os.getenv("ABUSEIPDB_URL", "https://api.abuseipdb.com/api/v2/check"),
            abuseipdb_timeout=int(os.getenv("ABUSEIPDB_TIMEOUT", "15")),
            abuseipdb_max_retries=int(os.getenv("ABUSEIPDB_MAX_RETRIES", "3")),
            abuseipdb_backoff=float(os.getenv("ABUSEIPDB_BACKOFF", "1.5")),
        )


@dataclass
class RequestEvent:
    timestamp: float
    path: str


@dataclass
class DetectionResult:
    ip: str
    reason: str
    request_count: int
    sensitive_hits: int
    unique_paths: int
    detected_at: float
    paths: list[str] = field(default_factory=list)  # Actual ClientRequestURI values


@dataclass
class BlockRecord:
    ip: str
    rule_id: str | None
    blocked_at: float
    reason: str


def build_logger(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("soar_module")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def load_master_blocked_ips(master_csv_path: Path, logger: logging.Logger) -> set[str]:
    """Load blocked IPs from master blocking sheet."""
    blocked_ips: set[str] = set()
    
    if not master_csv_path.exists():
        logger.warning("Master blocking sheet not found: %s", master_csv_path)
        return blocked_ips
    
    try:
        with master_csv_path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                if len(row) < 4:
                    continue
                # IP is typically in column 3 (index 3)
                ip_value = row[3].strip() if len(row) > 3 else ""
                if ip_value and not any(keyword in ip_value.lower() for keyword in ["ip", "address", "blocked"]):
                    blocked_ips.add(ip_value)
        logger.info("Loaded %d IPs from master blocking sheet", len(blocked_ips))
    except Exception as exc:
        logger.warning("Failed to load master blocking sheet: %s", exc)
    
    return blocked_ips


def load_whitelist(whitelist_csv_path: Path, logger: logging.Logger) -> tuple[set[str], set[str]]:
    """Load whitelisted IPs and CIDR blocks from whitelist CSV."""
    individual_ips: set[str] = set()
    cidr_blocks: set[str] = set()
    
    if not whitelist_csv_path.exists():
        logger.warning("Whitelist CSV not found: %s", whitelist_csv_path)
        return individual_ips, cidr_blocks
    
    try:
        with whitelist_csv_path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                for cell in row:
                    value = cell.strip()
                    if not value:
                        continue
                    
                    # Skip header-like entries
                    if any(keyword in value.lower() for keyword in ["region", "whitelisted", "proxy", "crawler", "range", "ip", "address", "office"]):
                        continue
                    
                    # Check if CIDR block
                    if "/" in value:
                        try:
                            ip_network(value)
                            cidr_blocks.add(value)
                        except (AddressValueError, ValueError):
                            pass
                    else:
                        # Try to parse as IP
                        try:
                            ip_address(value)
                            individual_ips.add(value)
                        except (AddressValueError, ValueError):
                            pass
        logger.info("Loaded %d whitelisted IPs and %d CIDR blocks", len(individual_ips), len(cidr_blocks))
    except Exception as exc:
        logger.warning("Failed to load whitelist: %s", exc)
    
    return individual_ips, cidr_blocks


def is_ip_whitelisted(ip: str, whitelist_ips: set[str], whitelist_cidrs: set[str]) -> bool:
    """Check if IP is in whitelist (exact match or CIDR range)."""
    if ip in whitelist_ips:
        return True
    
    try:
        ip_obj = ip_address(ip)
        for cidr in whitelist_cidrs:
            try:
                if ip_obj in ip_network(cidr):
                    return True
            except (AddressValueError, ValueError):
                continue
    except (AddressValueError, ValueError):
        pass
    
    return False


def is_ip_already_in_detected_threats(db_path: Path, ip: str) -> bool:
    """Check if IP already exists in detected_threats table."""
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM detected_threats WHERE ipAddress = ? LIMIT 1", (ip,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    except Exception:
        return False


def format_top_malicious_paths(paths: list[str], sensitive_paths: set[str], max_paths: int = 5) -> str:
    """Format top 5 malicious paths, prioritizing sensitive paths.
    
    Args:
        paths: List of ClientRequestURI values
        sensitive_paths: Set of sensitive path patterns
        max_paths: Maximum number of paths to include (default: 5)
    
    Returns:
        Comma-separated string of top malicious paths
    """
    if not paths:
        return ""
    
    # Count occurrences and separate sensitive vs normal
    path_counts = Counter(paths)
    sensitive_found = []
    normal_found = []
    
    for path, count in path_counts.most_common():
        if path in sensitive_paths:
            sensitive_found.append(path)
        else:
            normal_found.append(path)
    
    # Prioritize sensitive paths, then add normal paths to fill up to max_paths
    top_paths = sensitive_found[:max_paths]
    remaining_slots = max_paths - len(top_paths)
    if remaining_slots > 0:
        top_paths.extend(normal_found[:remaining_slots])
    
    return ", ".join(top_paths)


def validate_config(config: AppConfig, demo_mode: bool = False) -> None:
    if not config.log_input_path.exists():
        raise ValueError(f"LOG_INPUT_PATH does not exist: {config.log_input_path}")
    if config.scan_interval_seconds <= 0:
        raise ValueError("SCAN_INTERVAL_SECONDS must be > 0.")
    if not demo_mode:
        if not config.cloudflare_api_token:
            raise ValueError("CLOUDFLARE_API_TOKEN is required. Set env var or use DEMO_MODE=1 for testing.")
        if not config.zone_id:
            raise ValueError("ZONE_ID is required. Set env var or use DEMO_MODE=1 for testing.")


def parse_edge_timestamp(raw_value: Any) -> float:
    if raw_value is None:
        return time.time()

    try:
        if isinstance(raw_value, str):
            if raw_value.isdigit():
                value = int(raw_value)
            else:
                dt = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
                return dt.timestamp()
        else:
            value = int(raw_value)
    except Exception:
        return time.time()

    if value > 10**15:
        return value / 1_000_000_000
    if value > 10**12:
        return value / 1_000
    return float(value)


def iter_log_files(config: AppConfig) -> list[Path]:
    if config.log_input_path.is_file():
        return [config.log_input_path]
    return sorted(config.log_input_path.glob(config.log_glob))


def parse_logs(
    config: AppConfig,
    file_offsets: dict[str, int],
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for file_path in iter_log_files(config):
        file_key = str(file_path)
        try:
            file_size = file_path.stat().st_size
            offset = file_offsets.get(file_key, 0)
            if offset > file_size:
                offset = 0

            with file_path.open("r", encoding="utf-8") as infile:
                infile.seek(offset)
                for line in infile:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Invalid JSON line in %s", file_path)
                        continue

                    client_ip = str(payload.get("ClientIP", "")).strip()
                    if not client_ip:
                        continue

                    records.append(
                        {
                            "ClientIP": client_ip,
                            "ClientRequestURI": str(payload.get("ClientRequestURI", "")).strip() or "/",
                            "ClientRequestHost": str(payload.get("ClientRequestHost", "")).strip(),
                            "EdgeResponseStatus": payload.get("EdgeResponseStatus"),
                            "WAFAction": payload.get("WAFAction"),
                            "EdgeStartTimestamp": parse_edge_timestamp(payload.get("EdgeStartTimestamp")),
                        }
                    )

                file_offsets[file_key] = infile.tell()
        except Exception as exc:
            logger.exception("Failed parsing %s: %s", file_path, exc)

    return records


def cleanup_old_entries(
    ip_events: dict[str, deque[RequestEvent]],
    now_ts: float,
    window_seconds: int,
    detection_state: dict[str, float],
) -> None:
    window_start = now_ts - window_seconds
    removable_ips: list[str] = []

    for ip, events in ip_events.items():
        while events and events[0].timestamp < window_start:
            events.popleft()
        if not events:
            removable_ips.append(ip)

    for ip in removable_ips:
        ip_events.pop(ip, None)
        detection_state.pop(ip, None)


def detect_malicious_ips(
    records: list[dict[str, Any]],
    ip_events: dict[str, deque[RequestEvent]],
    detection_state: dict[str, float],
    config: AppConfig,
    logger: logging.Logger,
) -> list[DetectionResult]:
    detections: list[DetectionResult] = []

    records.sort(key=lambda item: float(item["EdgeStartTimestamp"]))

    for record in records:
        ip = record["ClientIP"]
        event_ts = float(record["EdgeStartTimestamp"])
        path = record["ClientRequestURI"] or "/"
        events = ip_events[ip]
        events.append(RequestEvent(timestamp=event_ts, path=path))

        window_start = event_ts - config.scan_interval_seconds
        while events and events[0].timestamp < window_start:
            events.popleft()

        request_count = len(events)
        path_counter = Counter(evt.path for evt in events)
        unique_paths = len(path_counter)
        sensitive_hits = sum(path_counter.get(sensitive_path, 0) for sensitive_path in config.sensitive_paths)

        reason: str | None = None
        if sensitive_hits > config.sensitive_path_threshold:
            reason = "sensitive_path_abuse"
        elif unique_paths > config.unique_path_threshold:
            reason = "scanner_behavior"
        elif request_count > config.request_threshold:
            reason = "high_request_rate"

        if reason is None:
            continue

        last_detected = detection_state.get(ip, 0)
        if event_ts - last_detected < config.scan_interval_seconds:
            continue

        detection_state[ip] = event_ts
        
        # Collect actual paths for this IP
        all_paths = [evt.path for evt in events]
        
        detection = DetectionResult(
            ip=ip,
            reason=reason,
            request_count=request_count,
            sensitive_hits=sensitive_hits,
            unique_paths=unique_paths,
            detected_at=event_ts,
            paths=all_paths,
        )
        detections.append(detection)
        logger.info(
            "Detection: ip=%s reason=%s requests=%s sensitive_hits=%s unique_paths=%s",
            detection.ip,
            detection.reason,
            detection.request_count,
            detection.sensitive_hits,
            detection.unique_paths,
        )

    return detections


def cloudflare_headers(config: AppConfig) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {config.cloudflare_api_token}",
        "Content-Type": "application/json",
    }


def get_existing_block_rule_id(
    session: requests.Session,
    config: AppConfig,
    ip_address: str,
    logger: logging.Logger,
) -> str | None:
    endpoint = f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/firewall/access_rules/rules"
    params = {
        "mode": "block",
        "configuration.target": "ip",
        "configuration.value": ip_address,
        "page": 1,
        "per_page": 50,
    }

    try:
        response = session.get(
            endpoint,
            headers=cloudflare_headers(config),
            params=params,
            timeout=config.request_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        if not payload.get("success"):
            logger.warning("Cloudflare existing-rule lookup failed for %s: %s", ip_address, payload)
            return None

        for item in payload.get("result", []):
            cfg = item.get("configuration", {})
            if cfg.get("target") == "ip" and cfg.get("value") == ip_address:
                return item.get("id")
    except requests.RequestException as exc:
        logger.exception("Cloudflare lookup request failed for %s: %s", ip_address, exc)
    except Exception as exc:
        logger.exception("Unexpected lookup error for %s: %s", ip_address, exc)

    return None


def block_ip(
    session: requests.Session,
    config: AppConfig,
    ip_address: str,
    reason: str,
    blocked_cache: dict[str, BlockRecord],
    logger: logging.Logger,
) -> bool:
    if ip_address in blocked_cache:
        logger.info("Skip block (already cached): %s", ip_address)
        return False

    existing_rule_id = get_existing_block_rule_id(session, config, ip_address, logger)
    if existing_rule_id:
        blocked_cache[ip_address] = BlockRecord(
            ip=ip_address,
            rule_id=existing_rule_id,
            blocked_at=time.time(),
            reason=reason,
        )
        logger.info("Skip block (already in Cloudflare): %s", ip_address)
        return False

    endpoint = f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/firewall/access_rules/rules"
    payload = {
        "mode": "block",
        "configuration": {"target": "ip", "value": ip_address},
        "notes": f"SOAR auto-block: {reason} at {datetime.now(timezone.utc).isoformat()}",
    }

    try:
        response = session.post(
            endpoint,
            headers=cloudflare_headers(config),
            json=payload,
            timeout=config.request_timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            logger.error("Cloudflare block failed for %s: %s", ip_address, data)
            return False

        rule_id = (data.get("result") or {}).get("id")
        blocked_cache[ip_address] = BlockRecord(
            ip=ip_address,
            rule_id=rule_id,
            blocked_at=time.time(),
            reason=reason,
        )
        logger.info("Blocked IP: %s reason=%s rule_id=%s", ip_address, reason, rule_id)
        return True
    except requests.RequestException as exc:
        logger.exception("Cloudflare block request failed for %s: %s", ip_address, exc)
    except Exception as exc:
        logger.exception("Unexpected block error for %s: %s", ip_address, exc)
    return False


def unblock_ip(
    session: requests.Session,
    config: AppConfig,
    ip_address: str,
    rule_id: str,
    logger: logging.Logger,
) -> bool:
    endpoint = f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/firewall/access_rules/rules/{rule_id}"
    try:
        response = session.delete(
            endpoint,
            headers=cloudflare_headers(config),
            timeout=config.request_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("success"):
            logger.info("Auto-unblocked IP: %s rule_id=%s", ip_address, rule_id)
            return True
        logger.warning("Auto-unblock failed for %s: %s", ip_address, payload)
    except requests.RequestException as exc:
        logger.exception("Cloudflare unblock request failed for %s: %s", ip_address, exc)
    except Exception as exc:
        logger.exception("Unexpected unblock error for %s: %s", ip_address, exc)
    return False


def save_block_state(state_file: Path, blocked_cache: dict[str, BlockRecord], logger: logging.Logger) -> None:
    try:
        serializable = {
            ip: {
                "ip": rec.ip,
                "rule_id": rec.rule_id,
                "blocked_at": rec.blocked_at,
                "reason": rec.reason,
            }
            for ip, rec in blocked_cache.items()
        }
        state_file.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.exception("Failed writing blocked state file: %s", exc)


def load_block_state(state_file: Path, logger: logging.Logger) -> dict[str, BlockRecord]:
    if not state_file.exists():
        return {}

    try:
        payload = json.loads(state_file.read_text(encoding="utf-8"))
        records: dict[str, BlockRecord] = {}
        for ip, data in payload.items():
            records[ip] = BlockRecord(
                ip=data.get("ip", ip),
                rule_id=data.get("rule_id"),
                blocked_at=float(data.get("blocked_at", time.time())),
                reason=str(data.get("reason", "unknown")),
            )
        return records
    except Exception as exc:
        logger.exception("Failed reading blocked state file: %s", exc)
        return {}


def upsert_soar_detection_to_db(
    db_path: Path,
    detection: DetectionResult,
    config: AppConfig,
    master_blocked_ips: set[str],
    whitelist_ips: set[str],
    whitelist_cidrs: set[str],
    logger: logging.Logger,
) -> bool:
    """Insert SOAR detection into scan_results and detected_threats (with verification).
    
    Returns:
        True if IP was inserted to detected_threats, False if skipped
    """
    try:
        # Check if IP is already blocked in master sheet
        if detection.ip in master_blocked_ips:
            logger.info("Skipping %s - already in master blocking sheet", detection.ip)
            return False
        
        # Check if IP is whitelisted
        if is_ip_whitelisted(detection.ip, whitelist_ips, whitelist_cidrs):
            logger.info("Skipping %s - IP is whitelisted", detection.ip)
            return False
        
        # Check if IP already exists in detected_threats to prevent duplicates
        if is_ip_already_in_detected_threats(db_path, detection.ip):
            logger.info("Skipping %s - already in detected threats", detection.ip)
            return False
        
        # Try to get ISP and country from existing scan_results (from previous AbuseIPDB scans)
        isp_value = ""
        country_value = ""
        
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT isp, country FROM scan_results WHERE ipAddress = ?", (detection.ip,))
        existing_scan = cursor.fetchone()
        
        if existing_scan and existing_scan[0]:
            # Reuse ISP and country from previous AbuseIPDB scan
            isp_value = existing_scan[0] or ""
            country_value = existing_scan[1] or ""
            logger.info("Reusing ISP from existing scan: %s (Country: %s)", isp_value, country_value)
        elif query_abuseipdb and config.abuseipdb_api_key:
            # Query AbuseIPDB for ISP and country information
            try:
                logger.info("Querying AbuseIPDB for %s to get ISP and country information", detection.ip)
                abuseipdb_data = query_abuseipdb(
                    ip_address=detection.ip,
                    api_key=config.abuseipdb_api_key,
                    api_url=config.abuseipdb_url,
                    timeout_seconds=config.abuseipdb_timeout,
                    max_retries=config.abuseipdb_max_retries,
                    retry_backoff_seconds=config.abuseipdb_backoff,
                )
                if abuseipdb_data:
                    # Use actual ISP and country from AbuseIPDB (even if empty)
                    isp_value = abuseipdb_data.get("isp") or ""
                    country_value = abuseipdb_data.get("countryCode") or ""
                    logger.info("AbuseIPDB returned ISP: '%s', Country: '%s'", isp_value, country_value)
                else:
                    logger.warning("AbuseIPDB query returned no data for %s", detection.ip)
            except Exception as exc:
                logger.warning("AbuseIPDB query failed for %s: %s", detection.ip, exc)
        else:
            logger.debug("AbuseIPDB not available, ISP and country will be empty")
        
        # Always mark as SOAR detection in countryCode field (used for filtering)
        source_marker = "SOAR"
        logger.debug("Marking %s as SOAR detection with country: %s", detection.ip, country_value or "(empty)")
        
        # Format top 5 malicious paths from logpush data
        formatted_paths = format_top_malicious_paths(detection.paths, config.sensitive_paths, max_paths=5)
        if not formatted_paths:
            formatted_paths = f"SOAR Detection - {detection.reason}"
        
        # Insert into scan_results table (for the scanned results view)
        cursor.execute(
            """
            INSERT INTO scan_results (
                ipAddress, abuseConfidenceScore, countryCode, country, isp, path
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ipAddress) DO UPDATE SET
                abuseConfidenceScore = excluded.abuseConfidenceScore,
                countryCode = excluded.countryCode,
                country = excluded.country,
                isp = excluded.isp,
                path = excluded.path
            """,
            (
                detection.ip,
                detection.request_count,  # Use request count as abuse score
                source_marker,  # Always "SOAR" for filtering
                country_value,  # Actual country code from AbuseIPDB
                isp_value,
                formatted_paths,
            ),
        )
        
        # Insert into detected_threats table (for the threats workflow)
        cursor.execute(
            """
            INSERT INTO detected_threats (
                ipAddress, abuseConfidenceScore, countryCode, country, isp, path, approval_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ipAddress) DO UPDATE SET
                abuseConfidenceScore = excluded.abuseConfidenceScore,
                countryCode = excluded.countryCode,
                country = excluded.country,
                isp = excluded.isp,
                path = excluded.path
            """,
            (
                detection.ip,
                detection.request_count,
                source_marker,  # Always "SOAR" for filtering
                country_value,  # Actual country code from AbuseIPDB
                isp_value,
                formatted_paths,
                "Pending",
            ),
        )
        
        conn.commit()
        conn.close()
        logger.info("✅ Inserted SOAR detection %s into database (ISP: %s, Paths: %s)", 
                   detection.ip, isp_value, formatted_paths[:100])
        return True
    except Exception as exc:
        logger.exception("Failed to insert SOAR detection to DB: %s", exc)
        return False


def auto_unblock_expired(
    session: requests.Session,
    config: AppConfig,
    blocked_cache: dict[str, BlockRecord],
    logger: logging.Logger,
) -> None:
    expiry_seconds = config.auto_unblock_hours * 3600
    now_ts = time.time()

    removable: list[str] = []
    for ip, record in blocked_cache.items():
        if now_ts - record.blocked_at < expiry_seconds:
            continue

        if not record.rule_id:
            removable.append(ip)
            continue

        if unblock_ip(session, config, ip, record.rule_id, logger):
            removable.append(ip)

    for ip in removable:
        blocked_cache.pop(ip, None)


def run() -> None:
    config = AppConfig.from_env()
    demo_mode = os.getenv("DEMO_MODE", "").strip().lower() in ("1", "true", "yes")
    validate_config(config, demo_mode=demo_mode)
    logger = build_logger(config.decision_log_file)

    if demo_mode:
        logger.info("="*60)
        logger.info("STARTING SOAR MODULE IN DEMO MODE")
        logger.info("Detections will be logged but NO actual blocking will occur")
        logger.info("="*60)
    else:
        logger.info("="*60)
        logger.info("STARTING SOAR MODULE IN PRODUCTION MODE")
        logger.info("Detected IPs will be blocked via Cloudflare API")
        logger.info("="*60)

    logger.info("Starting SOAR module with interval=%ss, window=%ss", config.scan_interval_seconds, config.scan_interval_seconds)
    
    # Load master blocking sheet and whitelist for verification
    logger.info("Loading master blocking sheet from: %s", config.master_sheet_path)
    master_blocked_ips = load_master_blocked_ips(config.master_sheet_path, logger)
    
    logger.info("Loading whitelist from: %s", config.whitelist_path)
    whitelist_ips, whitelist_cidrs = load_whitelist(config.whitelist_path, logger)

    file_offsets: dict[str, int] = {}
    ip_events: dict[str, deque[RequestEvent]] = defaultdict(deque)
    detection_state: dict[str, float] = {}
    blocked_cache = load_block_state(config.state_file, logger)
    
    # Reload interval for master sheet and whitelist (every 10 scans)
    scan_count = 0
    reload_interval = 10

    with requests.Session() as session:
        while True:
            loop_start = time.time()
            try:
                # Periodically reload master sheet and whitelist
                scan_count += 1
                if scan_count >= reload_interval:
                    logger.info("Reloading master blocking sheet and whitelist...")
                    master_blocked_ips = load_master_blocked_ips(config.master_sheet_path, logger)
                    whitelist_ips, whitelist_cidrs = load_whitelist(config.whitelist_path, logger)
                    scan_count = 0
                
                auto_unblock_expired(session, config, blocked_cache, logger)

                records = parse_logs(config, file_offsets, logger)
                detections = detect_malicious_ips(records, ip_events, detection_state, config, logger)

                for detection in detections:
                    # Add to detected threats database (with verification)
                    inserted = upsert_soar_detection_to_db(
                        config.sqlite_db_path,
                        detection,
                        config,
                        master_blocked_ips,
                        whitelist_ips,
                        whitelist_cidrs,
                        logger
                    )
                    
                    if not inserted:
                        # IP was skipped due to verification checks
                        continue
                    
                    if demo_mode:
                        logger.info(
                            "[DEMO MODE] Would block IP: %s reason=%s requests=%s (added to detected threats)",
                            detection.ip,
                            detection.reason,
                            detection.request_count,
                        )
                    else:
                        block_ip(
                            session=session,
                            config=config,
                            ip_address=detection.ip,
                            reason=detection.reason,
                            blocked_cache=blocked_cache,
                            logger=logger,
                        )

                cleanup_old_entries(
                    ip_events=ip_events,
                    now_ts=loop_start,
                    window_seconds=config.scan_interval_seconds,
                    detection_state=detection_state,
                )

                save_block_state(config.state_file, blocked_cache, logger)
            except Exception as exc:
                logger.exception("Main loop error: %s", exc)

            elapsed = time.time() - loop_start
            sleep_for = max(1, config.scan_interval_seconds - int(elapsed))
            time.sleep(sleep_for)


if __name__ == "__main__":
    run()