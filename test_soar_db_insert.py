#!/usr/bin/env python3
"""Quick test to verify SOAR can insert into database."""

import sqlite3
from pathlib import Path

db_path = Path("soc_ip_governance.db")

# Insert a test SOAR detection
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Insert test SOAR detection
test_ip = "192.0.2.123"
cursor.execute(
    """
    INSERT INTO scan_results (
        ipAddress, abuseConfidenceScore, countryCode, isp, PATH
    ) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(ipAddress) DO UPDATE SET
        abuseConfidenceScore = excluded.abuseConfidenceScore
    """,
    (test_ip, 25, "SOAR", "SOAR:sensitive_path_abuse", "Test SOAR detection"),
)

cursor.execute(
    """
    INSERT INTO detected_threats (
        ipAddress, abuseConfidenceScore, countryCode, isp, PATH, approval_status
    ) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(ipAddress) DO UPDATE SET
        abuseConfidenceScore = excluded.abuseConfidenceScore
    """,
    (test_ip, 25, "SOAR", "SOAR:sensitive_path_abuse", "Test SOAR detection", "Pending"),
)

conn.commit()

# Verify
cursor.execute("SELECT * FROM scan_results WHERE countryCode = 'SOAR'")
scan_results = cursor.fetchall()
cursor.execute("SELECT * FROM detected_threats WHERE countryCode = 'SOAR'")
threat_results = cursor.fetchall()

conn.close()

print("✅ Test SOAR detection inserted successfully!")
print(f"   - scan_results: {len(scan_results)} SOAR entries")
print(f"   - detected_threats: {len(threat_results)} SOAR entries")
print(f"\nTest IP: {test_ip}")
print("Go to 'Detected Threats' tab and refresh - you should see this test IP with 🔍 SOAR icon")

