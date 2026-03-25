#!/usr/bin/env python3
"""Generate a test logpush file with malicious IP patterns."""

import json
import random
from datetime import datetime, timedelta

output_file = "logpush_test_malicious.json"

# Define malicious IP patterns
malicious_patterns = {
    # High volume attackers (>20 requests)
    "198.51.100.10": {"type": "high_volume", "requests": 35, "paths": ["/api/v1/users", "/api/v1/products"]},
    "198.51.100.11": {"type": "high_volume", "requests": 42, "paths": ["/search", "/products"]},
    "198.51.100.12": {"type": "high_volume", "requests": 28, "paths": ["/"]},
    
    # Scanner IPs (>10 unique paths)
    "203.0.113.50": {"type": "scanner", "requests": 15, "paths": [f"/path{i}" for i in range(15)]},
    "203.0.113.51": {"type": "scanner", "requests": 12, "paths": [f"/admin/{i}" for i in range(12)]},
    "203.0.113.52": {"type": "scanner", "requests": 18, "paths": [f"/api/v{i}/test" for i in range(18)]},
    
    # Sensitive path abuse (>5 hits to sensitive paths)
    "192.0.2.100": {"type": "sensitive", "requests": 8, "paths": ["/wp-login.php"] * 8},
    "192.0.2.101": {"type": "sensitive", "requests": 10, "paths": ["/admin"] * 7 + ["/login"] * 3},
    "192.0.2.102": {"type": "sensitive", "requests": 6, "paths": ["/.env"] * 6},
    
    # Multi-pattern attackers (triggers multiple detections)
    "10.0.0.50": {"type": "multi", "requests": 25, "paths": ["/wp-login.php"] * 10 + [f"/test{i}" for i in range(15)]},
    "10.0.0.51": {"type": "multi", "requests": 30, "paths": ["/admin"] * 8 + [f"/api/{i}" for i in range(22)]},
}

# Generate log entries
entries = []
base_time = datetime.now()

for ip, pattern in malicious_patterns.items():
    for idx in range(pattern["requests"]):
        path = random.choice(pattern["paths"])
        timestamp = (base_time - timedelta(seconds=random.randint(0, 3600))).isoformat()
        
        entry = {
            "ClientIP": ip,
            "ClientRequestURI": path,
            "EdgeStartTimestamp": int(base_time.timestamp() * 1000),
            "EdgeResponseStatus": random.choice([200, 404, 403, 500]),
            "ClientRequestMethod": "GET",
        }
        entries.append(entry)

# Add some normal traffic
for i in range(50):
    normal_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
    entry = {
        "ClientIP": normal_ip,
        "ClientRequestURI": random.choice(["/", "/home", "/about", "/contact"]),
        "EdgeStartTimestamp": int(base_time.timestamp() * 1000),
        "EdgeResponseStatus": 200,
        "ClientRequestMethod": "GET",
    }
    entries.append(entry)

# Write to newline-delimited JSON
with open(output_file, "w") as f:
    for entry in entries:
        f.write(json.dumps(entry) + "\n")

print(f"✅ Created {output_file} with {len(entries)} log entries")
print(f"\n📊 Malicious IP Summary:")
print(f"   - High volume IPs (>20 requests): 3")
print(f"   - Scanner IPs (>10 unique paths): 3")
print(f"   - Sensitive path abuse (>5 hits): 3")
print(f"   - Multi-pattern attackers: 2")
print(f"\nExpected detections: ~11 malicious IPs")
