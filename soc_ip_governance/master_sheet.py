"""Master blocked sheet operations."""

from __future__ import annotations

import csv
import logging
from datetime import datetime
from pathlib import Path

from ip_validator import is_valid_ipv4, is_valid_ipv6

logger = logging.getLogger(__name__)


MASTER_COLUMNS = [
    "Date",
    "Shift Member Name",
    "Blocked IP Address",
    "Reason for Blocking",
    "Time of Blocking",
    "Approval Status",
    "Remarks/Additional Notes",
    "Abusive Percentage(AbuseIPDB)",
    "Status(Blocked / Pending)",
    "Email Send Status",
]


APPROVAL_STATUSES = {"approved", "pending", "rejected"}


def _looks_like_time(value: str) -> bool:
    """Return True for common time strings like 09:46 AM."""

    text = value.strip().upper()
    return ":" in text and ("AM" in text or "PM" in text)


def _looks_like_reason(value: str) -> bool:
    """Heuristic to identify reason text."""

    text = value.strip().lower()
    if not text:
        return False
    reason_keywords = (
        "malicious",
        "activity",
        "abuse",
        "attack",
        "scan",
        "scanner",
        "phishing",
        "bruteforce",
        "brute force",
        "ddos",
        "bot",
    )
    return any(keyword in text for keyword in reason_keywords)


def normalize_master_sheet_row(row: list[str]) -> list[str]:
    """Normalize a CSV row into 10-column master sheet display schema.

    Target schema:
    [Date, Shift Member Name, Blocked IP Address, Reason for Blocking,
     Time of Blocking, Approval Status, Remarks/Additional Notes,
     Abusive Percentage(AbuseIPDB), Status(Blocked / Pending), Email Send Status]
    """

    values = [str(cell).strip() for cell in row]

    if values and values[0].strip().lower() in {"false", "true"}:
        values = values[1:]

    if len(values) >= 10:
        first_ten = values[:10]
        approval = first_ten[5].strip().lower()

        # Legacy 10-col format (after dropping FALSE) with ISP in col[3] and reason in col[6].
        if (
            approval in APPROVAL_STATUSES
            and _looks_like_time(first_ten[4])
            and not _looks_like_reason(first_ten[3])
            and _looks_like_reason(first_ten[6])
        ):
            return [
                first_ten[0],
                first_ten[1],
                first_ten[2],
                first_ten[6],
                first_ten[4],
                first_ten[5],
                first_ten[3],
                first_ten[7],
                first_ten[8],
                first_ten[9] or "NA",
            ]

        if not first_ten[9]:
            first_ten[9] = "NA"

        return first_ten

    if len(values) == 9:
        # Variant A: [Date, Name, IP, Reason, Time, Approval, Notes, Abuse, Status]
        # Variant B: [Date, Name, IP, ISP, Time, Approval, Reason, Abuse, Status]
        if values[5].strip().lower() in APPROVAL_STATUSES and _looks_like_time(values[4]):
            if _looks_like_reason(values[3]) or not values[6]:
                return [values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8], "NA"]
            return [values[0], values[1], values[2], values[6], values[4], values[5], values[3], values[7], values[8], "NA"]

    padded = (values + [""] * 10)[:10]
    if not padded[6]:
        padded[6] = "NA"
    if not padded[9]:
        padded[9] = "NA"
    return padded


def _find_ip_index(row: list[str]) -> int | None:
    """Locate IP address column index in a row across supported sheet formats."""

    candidate_indices = [3, 2]
    for index in candidate_indices:
        if index < len(row):
            value = row[index].strip()
            if is_valid_ipv4(value) or is_valid_ipv6(value):
                return index

    for index, value in enumerate(row):
        ip_value = value.strip()
        if is_valid_ipv4(ip_value) or is_valid_ipv6(ip_value):
            return index

    return None


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
                ip_index = _find_ip_index(row)
                if ip_index is None:
                    continue
                blocked_ips.add(row[ip_index].strip())
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
    reason: str = "High Abuse Rate",
    approval_status: str = "Approved",
    country: str = "",
    isp: str = "",
    abusive_percentage: str = "",
    final_status: str = "Blocked",
    selection_flag: str = "FALSE",
    email_send_status: str = "Pending",
) -> bool:
    """Append an approved IP to master sheet in 10-column dashboard format."""

    blocked_ips = load_master_blocked_ips(master_csv_path)
    if ip_address in blocked_ips:
        logger.info("IP %s already present in master sheet; skipping append.", ip_address)
        return False

    master_csv_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    row = [
        now.strftime("%d-%m-%Y"),
        name.strip() or "SOC Analyst",
        ip_address,
        reason.strip() or "Malicious Activity",
        now.strftime("%I:%M %p"),
        approval_status,
        notes.strip() if notes.strip() else "NA",
        str(abusive_percentage).strip() if str(abusive_percentage).strip() else "NA",
        final_status,
        email_send_status.strip() or "Pending",
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
            normalized = normalize_master_sheet_row(row)
            if normalized[2].strip() == ip_address:
                normalized[1] = name.strip() or "SOC Analyst"
                normalized[3] = reason.strip() or "High Abuse Rate"
                normalized[6] = notes.strip() or "NA"
                row[:] = normalized
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
        filtered_rows: list[list[str]] = []
        for row in rows:
            normalized = normalize_master_sheet_row(row)
            if normalized[2].strip() == ip_address:
                continue
            filtered_rows.append(row)
        rows = filtered_rows

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


def update_email_send_status(master_csv_path: Path, ip_addresses: list[str], email_status: str) -> int:
    """Update Email Send Status column for provided IP addresses.

    Returns number of rows updated.
    """

    if not master_csv_path.exists() or not ip_addresses:
        return 0

    normalized_targets = {ip.strip() for ip in ip_addresses if ip.strip()}
    if not normalized_targets:
        return 0

    try:
        rows = read_master_sheet_rows(master_csv_path)
        updated_count = 0

        for row in rows:
            normalized = normalize_master_sheet_row(row)
            if normalized[2].strip() in normalized_targets:
                normalized[9] = email_status.strip() or "NA"
                row[:] = normalized
                updated_count += 1

        if updated_count:
            with master_csv_path.open("w", encoding="utf-8", newline="") as csv_file:
                writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
                writer.writerows(rows)

        return updated_count
    except Exception:
        logger.exception("Failed to update email send status for %d IPs", len(normalized_targets))
        return 0
