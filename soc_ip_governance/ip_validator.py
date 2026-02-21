"""Validation and preprocessing helpers for IP inputs."""

from __future__ import annotations

import re
from typing import Iterable

# IPv4 regex with strict octet range 0-255
_IPV4_PATTERN = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)

# Practical IPv6 regex supporting full and compressed forms
_IPV6_PATTERN = re.compile(
    r"^((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|"
    r"[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|"
    r":(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))$"
)


def is_valid_ipv4(value: str) -> bool:
    """Return True when value is a syntactically valid IPv4 address."""

    return bool(_IPV4_PATTERN.match(value.strip()))


def is_valid_ipv6(value: str) -> bool:
    """Return True when value is a syntactically valid IPv6 address."""

    return bool(_IPV6_PATTERN.match(value.strip()))


def extract_valid_ips(raw_text: str) -> tuple[list[str], list[str], int]:
    """Extract valid IPs and invalid entries from multiline input.

    Returns:
        valid_ips: list of valid IP strings in original order
        invalid_entries: list of rejected lines
        total_lines: total non-empty lines received
    """

    valid_ips: list[str] = []
    invalid_entries: list[str] = []

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    total_lines = len(lines)

    for line in lines:
        # Basic input sanitization for unreasonable line length.
        candidate = line[:200].strip()
        if is_valid_ipv4(candidate) or is_valid_ipv6(candidate):
            valid_ips.append(candidate)
        else:
            invalid_entries.append(line)

    return valid_ips, invalid_entries, total_lines


def remove_duplicates(ips: Iterable[str]) -> tuple[list[str], int]:
    """Remove duplicate IPs while preserving order."""

    seen: set[str] = set()
    unique: list[str] = []
    duplicate_count = 0

    for ip_addr in ips:
        if ip_addr in seen:
            duplicate_count += 1
            continue
        seen.add(ip_addr)
        unique.append(ip_addr)

    return unique, duplicate_count


def generate_summary_stats(
    total_lines: int,
    valid_ips: list[str],
    invalid_entries: list[str],
    duplicate_count: int,
    already_blocked_count: int,
    ips_checked: int,
    detected_count: int,
) -> dict[str, int]:
    """Generate required processing summary metrics."""

    return {
        "Total lines received": total_lines,
        "Valid IPs": len(valid_ips),
        "Invalid entries removed": len(invalid_entries),
        "Duplicates removed": duplicate_count,
        "Already blocked removed": already_blocked_count,
        "New IPs checked": ips_checked,
        "Detected malicious IPs": detected_count,
    }
