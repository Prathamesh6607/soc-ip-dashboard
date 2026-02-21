"""Application configuration for SOC IP Governance."""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_MASTER_SHEET = BASE_DIR.parent / "IP Blocking - Sheet6.csv"
DEFAULT_WHITELIST_SHEET = BASE_DIR.parent / "ip_not_blocked.csv"
CONFIG_INI_PATH = BASE_DIR / "config.ini"


def _read_ini_value(section: str, key: str, default: str = "") -> str:
    """Read a value from local config.ini file, safely."""

    parser = configparser.ConfigParser()
    if not CONFIG_INI_PATH.exists():
        return default

    parser.read(CONFIG_INI_PATH, encoding="utf-8")
    return parser.get(section, key, fallback=default)


def _env_or_ini(env_key: str, section: str, ini_key: str, default: str = "") -> str:
    """Return environment value first, then config.ini, then default."""

    env_value = os.getenv(env_key)
    if env_value is not None and env_value != "":
        return env_value
    return _read_ini_value(section, ini_key, default)


@dataclass(frozen=True)
class AppConfig:
    """Static application settings."""

    abuseipdb_api_key: str = _env_or_ini("ABUSEIPDB_API_KEY", "abuseipdb", "api_key", "")
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"
    confidence_threshold: int = int(_env_or_ini("ABUSEIPDB_THRESHOLD", "abuseipdb", "threshold", "8"))
    timeout_seconds: int = int(_env_or_ini("ABUSEIPDB_TIMEOUT", "abuseipdb", "timeout_seconds", "15"))
    max_retries: int = int(_env_or_ini("ABUSEIPDB_MAX_RETRIES", "abuseipdb", "max_retries", "3"))
    retry_backoff_seconds: float = float(_env_or_ini("ABUSEIPDB_BACKOFF", "abuseipdb", "retry_backoff_seconds", "1.5"))
    master_sheet_path: Path = Path(
        _env_or_ini("MASTER_BLOCK_SHEET", "paths", "master_sheet", str(DEFAULT_MASTER_SHEET))
    )
    whitelist_sheet_path: Path = Path(
        _env_or_ini("WHITELIST_SHEET", "paths", "whitelist_sheet", str(DEFAULT_WHITELIST_SHEET))
    )
    sqlite_path: Path = Path(_env_or_ini("SOC_DB_PATH", "paths", "sqlite_db", str(BASE_DIR / "soc_ip_governance.db")))
    default_approver_name: str = _env_or_ini("SOC_APPROVER_NAME", "app", "default_approver_name", "SOC Analyst")
    default_reason: str = "Malicious Activity"
    smtp_host: str = _env_or_ini("SMTP_HOST", "email", "smtp_host", "")
    smtp_port: int = int(_env_or_ini("SMTP_PORT", "email", "smtp_port", "587"))
    smtp_username: str = _env_or_ini("SMTP_USERNAME", "email", "smtp_username", "")
    smtp_password: str = _env_or_ini("SMTP_PASSWORD", "email", "smtp_password", "")
    smtp_use_tls: bool = _env_or_ini("SMTP_USE_TLS", "email", "smtp_use_tls", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    email_from: str = _env_or_ini("EMAIL_FROM", "email", "email_from", "")
    email_to: str = _env_or_ini("EMAIL_TO", "email", "email_to", "")
    monitoring_emails: str = _env_or_ini("MONITORING_EMAILS", "email", "monitoring_emails", "")
    approval_receiver_email: str = _env_or_ini(
        "APPROVAL_RECEIVER_EMAIL", "email", "approval_receiver_email", "prathameshpendkar2005@gmail.com"
    )
    email_provider: str = _env_or_ini("EMAIL_PROVIDER", "email", "provider", "auto")
    gmail_credentials_file: Path = Path(
        _env_or_ini("GMAIL_CREDENTIALS_FILE", "gmail_api", "credentials_file", str(BASE_DIR / "gmail_credentials.json"))
    )
    gmail_token_file: Path = Path(
        _env_or_ini("GMAIL_TOKEN_FILE", "gmail_api", "token_file", str(BASE_DIR / "gmail_token.json"))
    )
    gmail_user_id: str = _env_or_ini("GMAIL_USER_ID", "gmail_api", "user_id", "me")


CONFIG = AppConfig()
