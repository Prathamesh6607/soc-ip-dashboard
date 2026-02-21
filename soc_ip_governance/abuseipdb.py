"""AbuseIPDB API integration module."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)


def query_abuseipdb(
    ip_address: str,
    api_key: str,
    api_url: str,
    timeout_seconds: int = 15,
    max_retries: int = 3,
    retry_backoff_seconds: float = 1.5,
) -> dict[str, Any] | None:
    """Query AbuseIPDB check endpoint and return normalized IP threat details."""

    if not api_key:
        logger.error("AbuseIPDB API key is missing.")
        return None

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(api_url, headers=headers, params=params, timeout=timeout_seconds)

            if response.status_code == 429:
                sleep_seconds = retry_backoff_seconds * attempt
                logger.warning(
                    "Rate limited by AbuseIPDB for %s (attempt %s/%s). Retrying in %.1fs.",
                    ip_address,
                    attempt,
                    max_retries,
                    sleep_seconds,
                )
                time.sleep(sleep_seconds)
                continue

            response.raise_for_status()
            payload = response.json().get("data", {})

            return {
                "ipAddress": payload.get("ipAddress", ip_address),
                "abuseConfidenceScore": int(payload.get("abuseConfidenceScore", 0)),
                "countryCode": payload.get("countryCode", ""),
                "isp": payload.get("isp", ""),
                "PATH": "",
            }
        except requests.RequestException:
            logger.exception("AbuseIPDB request failed for %s", ip_address)
            if attempt < max_retries:
                time.sleep(retry_backoff_seconds * attempt)
            continue
        except (TypeError, ValueError):
            logger.exception("Invalid AbuseIPDB response format for %s", ip_address)
            return None

    logger.error("Exhausted retries for AbuseIPDB check on %s", ip_address)
    return None
