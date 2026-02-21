"""Master blocked sheet operations."""

from __future__ import annotations

import csv
import logging
from datetime import datetime
from pathlib import Path

from ip_validator import is_valid_ipv4, is_valid_ipv6

logger = logging.getLogger(__name__)


MASTER_COLUMNS = [
    "YYYY-MM-DD",
    "Name",
    "IP Address",
    "Reason",
    "HH:MM AM/PM",
    "",
    "Notes",
    " ",
    "  ",
]


def load_master_blocked_ips(master_csv_path: Path) -> set[str]:
    """Load authoritative blocked IPs from the master CSV sheet."""

    blocked_ips: set[str] = set()

    if not master_csv_path.exists():
        logger.warning("Master sheet does not exist yet: %s", master_csv_path)
        return blocked_ips

    try:
        with master_csv_path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                if len(row) < 3:
                    continue
                ip_value = row[2].strip()
                if is_valid_ipv4(ip_value) or is_valid_ipv6(ip_value):
                    blocked_ips.add(ip_value)
    except Exception:
        logger.exception("Failed to load master blocked IPs from %s", master_csv_path)

    return blocked_ips


def read_master_sheet_rows(master_csv_path: Path) -> list[list[str]]:
    """Return all rows from master CSV exactly as stored."""

    rows: list[list[str]] = []
    if not master_csv_path.exists():
        return rows

    with master_csv_path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            if row:
                rows.append(row)

    return rows


def filter_already_blocked(ips: list[str], blocked_ips: set[str]) -> tuple[list[str], int]:
    """Filter out IP addresses already in authoritative blocked list."""

    new_ips = [ip_addr for ip_addr in ips if ip_addr not in blocked_ips]
    removed_count = len(ips) - len(new_ips)
    return new_ips, removed_count


def append_to_master_sheet(
    master_csv_path: Path,
    name: str,
    ip_address: str,
    notes: str,
    shift: str = "Morning",
    reason: str = "Malicious Activity",
) -> bool:
    """Append an approved IP to master sheet in strict format.

    Row format:
    YYYY-MM-DD,[Name],[IP Address],"Malicious Activity",HH:MM AM/PM,,[Notes | Shift: SHIFT],,
    """

    blocked_ips = load_master_blocked_ips(master_csv_path)
    if ip_address in blocked_ips:
        logger.info("IP %s already present in master sheet; skipping append.", ip_address)
        return False

    master_csv_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    notes_with_shift = f"{notes.strip() if notes else 'Approved by SOC'} | Shift: {shift}"
    row = [
        now.strftime("%Y-%m-%d"),
        name.strip() or "SOC Analyst",
        ip_address,
        reason,
        now.strftime("%I:%M %p"),
        "",
        notes_with_shift,
        "",
        "",
    ]

    try:
        with master_csv_path.open("a", encoding="utf-8", newline="") as csv_file:
            writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(row)
        return True
    except Exception:
        logger.exception("Failed to append IP %s to master sheet", ip_address)
        return False


def update_master_sheet_row(
    master_csv_path: Path,
    ip_address: str,
    name: str,
    reason: str,
    notes: str,
) -> bool:
    """Update an existing row in master sheet by IP address."""

    if not master_csv_path.exists():
        logger.warning("Master sheet does not exist: %s", master_csv_path)
        return False

    try:
        rows = read_master_sheet_rows(master_csv_path)
        updated = False

        for row in rows:
            if len(row) >= 3 and row[2].strip() == ip_address:
                row[1] = name.strip() or "SOC Analyst"
                row[3] = reason.strip() or "Malicious Activity"
                if len(row) > 6:
                    row[6] = notes.strip() or "Updated by SOC"
                updated = True
                break

        if not updated:
            logger.warning("IP %s not found in master sheet", ip_address)
            return False

        with master_csv_path.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
            writer.writerows(rows)
        return True
    except Exception:
        logger.exception("Failed to update IP %s in master sheet", ip_address)
        return False


def delete_master_sheet_row(master_csv_path: Path, ip_address: str) -> bool:
    """Delete a row from master sheet by IP address."""

    if not master_csv_path.exists():
        logger.warning("Master sheet does not exist: %s", master_csv_path)
        return False

    try:
        rows = read_master_sheet_rows(master_csv_path)
        original_count = len(rows)
        rows = [row for row in rows if len(row) < 3 or row[2].strip() != ip_address]

        if len(rows) == original_count:
            logger.warning("IP %s not found in master sheet", ip_address)
            return False

        with master_csv_path.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
            writer.writerows(rows)
        return True
    except Exception:
        logger.exception("Failed to delete IP %s from master sheet", ip_address)
        return False
