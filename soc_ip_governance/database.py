"""SQLite persistence for detected threats."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


def init_database(db_path: Path) -> None:
    """Initialize SQLite database and tables."""

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                ipAddress TEXT PRIMARY KEY,
                abuseConfidenceScore INTEGER NOT NULL,
                countryCode TEXT,
                country TEXT,
                isp TEXT,
                path TEXT,
                last_checked_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detected_threats (
                ipAddress TEXT PRIMARY KEY,
                abuseConfidenceScore INTEGER NOT NULL,
                countryCode TEXT,
                country TEXT,
                isp TEXT,
                path TEXT,
                approval_status TEXT DEFAULT 'Pending',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS custom_whitelist (
                entry TEXT PRIMARY KEY,
                entry_type TEXT NOT NULL CHECK(entry_type IN ('IP', 'CIDR')),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def upsert_scan_result(db_path: Path, record: dict[str, Any]) -> None:
    """Insert or update a raw AbuseIPDB scan result."""

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scan_results (ipAddress, abuseConfidenceScore, countryCode, country, isp, path)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ipAddress)
            DO UPDATE SET
                abuseConfidenceScore = excluded.abuseConfidenceScore,
                countryCode = excluded.countryCode,
                country = excluded.country,
                isp = excluded.isp,
                path = excluded.path,
                last_checked_at = CURRENT_TIMESTAMP
            """,
            (
                record.get("ipAddress", ""),
                int(record.get("abuseConfidenceScore", 0)),
                record.get("countryCode", ""),
                record.get("country", ""),
                record.get("isp", ""),
                record.get("PATH", ""),
            ),
        )
        conn.commit()


def upsert_detected_threat(db_path: Path, record: dict[str, Any]) -> None:
    """Insert or update a detected threat record."""

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO detected_threats (ipAddress, abuseConfidenceScore, countryCode, country, isp, path, approval_status)
            VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, 'Pending'))
            ON CONFLICT(ipAddress)
            DO UPDATE SET
                abuseConfidenceScore = excluded.abuseConfidenceScore,
                countryCode = excluded.countryCode,
                country = excluded.country,
                isp = excluded.isp,
                path = excluded.path,
                approval_status = excluded.approval_status
            """,
            (
                record.get("ipAddress", ""),
                int(record.get("abuseConfidenceScore", 0)),
                record.get("countryCode", ""),
                record.get("country", ""),
                record.get("isp", ""),
                record.get("PATH", ""),
                record.get("Approval Status", "Pending"),
            ),
        )
        conn.commit()


def update_approval_status(db_path: Path, ip_address: str, status: str) -> None:
    """Update approval status for one IP."""

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE detected_threats SET approval_status = ? WHERE ipAddress = ?",
            (status, ip_address),
        )
        conn.commit()


def fetch_detected_threats(db_path: Path) -> list[dict[str, Any]]:
    """Fetch all detected threats ordered by score desc."""

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT ipAddress, abuseConfidenceScore, countryCode, country, isp, path, approval_status
            FROM detected_threats
            ORDER BY abuseConfidenceScore DESC, ipAddress ASC
            """
        ).fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "ipAddress": row["ipAddress"],
                "abuseConfidenceScore": row["abuseConfidenceScore"],
                "countryCode": row["countryCode"],
                "country": row["country"] or "",
                "isp": row["isp"],
                "PATH": row["path"] or "",
                "Approval Status": row["approval_status"] or "Pending",
            }
        )
    return results


def fetch_scan_results(db_path: Path, min_score: int = 20) -> list[dict[str, Any]]:
    """Fetch unique AbuseIPDB scan results with score >= min_score, ordered by score desc."""

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT ipAddress, abuseConfidenceScore, countryCode, country, isp, path
            FROM scan_results
            WHERE abuseConfidenceScore >= ?
            ORDER BY abuseConfidenceScore DESC, ipAddress ASC
            """,
            (min_score,),
        ).fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "ipAddress": row["ipAddress"],
                "abuseConfidenceScore": row["abuseConfidenceScore"],
                "countryCode": row["countryCode"],
                "country": row["country"] or "",
                "isp": row["isp"],
                "PATH": row["path"] or "",
            }
        )
    return results


def update_scan_result_path(db_path: Path, ip_address: str, path: str) -> None:
    """Update PATH column for a scanned IP result in both scan_results and detected_threats."""

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE scan_results SET path = ? WHERE ipAddress = ?",
            (path, ip_address),
        )
        # Also update in detected_threats if the IP exists there
        conn.execute(
            "UPDATE detected_threats SET path = ? WHERE ipAddress = ?",
            (path, ip_address),
        )
        conn.commit()


def clear_all_scan_results(db_path: Path) -> int:
    """Delete all records from scan_results table. Returns number of rows deleted."""

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("DELETE FROM scan_results")
        conn.commit()
        return cursor.rowcount


def upsert_custom_whitelist_entry(db_path: Path, entry: str, entry_type: str) -> None:
    """Insert or update a custom whitelist entry."""

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO custom_whitelist (entry, entry_type)
            VALUES (?, ?)
            ON CONFLICT(entry)
            DO UPDATE SET entry_type = excluded.entry_type
            """,
            (entry, entry_type),
        )
        conn.commit()


def delete_custom_whitelist_entry(db_path: Path, entry: str) -> bool:
    """Delete one custom whitelist entry by exact value."""

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("DELETE FROM custom_whitelist WHERE entry = ?", (entry,))
        conn.commit()
        return cursor.rowcount > 0


def fetch_custom_whitelist_entries(db_path: Path) -> list[dict[str, Any]]:
    """Fetch all custom whitelist entries ordered by newest first."""

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT entry, entry_type, created_at
            FROM custom_whitelist
            ORDER BY datetime(created_at) DESC, entry ASC
            """
        ).fetchall()

    return [
        {
            "entry": row["entry"],
            "entry_type": row["entry_type"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
