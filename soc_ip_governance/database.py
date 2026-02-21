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
                isp TEXT,
                path TEXT,
                approval_status TEXT DEFAULT 'Pending',
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
            INSERT INTO scan_results (ipAddress, abuseConfidenceScore, countryCode, isp, path)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ipAddress)
            DO UPDATE SET
                abuseConfidenceScore = excluded.abuseConfidenceScore,
                countryCode = excluded.countryCode,
                isp = excluded.isp,
                path = excluded.path,
                last_checked_at = CURRENT_TIMESTAMP
            """,
            (
                record.get("ipAddress", ""),
                int(record.get("abuseConfidenceScore", 0)),
                record.get("countryCode", ""),
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
            INSERT INTO detected_threats (ipAddress, abuseConfidenceScore, countryCode, isp, path, approval_status)
            VALUES (?, ?, ?, ?, ?, COALESCE(?, 'Pending'))
            ON CONFLICT(ipAddress)
            DO UPDATE SET
                abuseConfidenceScore = excluded.abuseConfidenceScore,
                countryCode = excluded.countryCode,
                isp = excluded.isp,
                path = excluded.path,
                approval_status = excluded.approval_status
            """,
            (
                record.get("ipAddress", ""),
                int(record.get("abuseConfidenceScore", 0)),
                record.get("countryCode", ""),
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
            SELECT ipAddress, abuseConfidenceScore, countryCode, isp, path, approval_status
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
            SELECT ipAddress, abuseConfidenceScore, countryCode, isp, path
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
