#!/usr/bin/env python3
"""Add malicious IP patterns to existing logpush_simulation.json file."""

import json
import random
from datetime import datetime, timedelta

# Define malicious IP patterns to add
malicious_patterns = {
    # High volume attackers (>20 requests) - same IP, various normal paths
    "203.0.113.10": {
        "type": "high_volume",
        "requests": 35,
        "paths": ["/api/v1/users", "/api/v1/products", "/search", "/products", "/dashboard"] * 7,
    },
    "203.0.113.11": {
        "type": "high_volume", 
        "requests": 42,
        "paths": ["/search", "/products", "/cart", "/checkout", "/"]  * 9,
    },
    "203.0.113.12": {
        "type": "high_volume",
        "requests": 28,
        "paths": ["/", "/home", "/about"] * 10,
    },
    
    # Scanner IPs (>10 unique paths) - different paths each request
    "198.51.100.50": {
        "type": "scanner",
        "requests": 15,
        "paths": [f"/path{i}" for i in range(15)],
    },
    "198.51.100.51": {
        "type": "scanner",
        "requests": 12,
        "paths": [f"/admin/section{i}" for i in range(12)],
    },
    "198.51.100.52": {
        "type": "scanner",
        "requests": 18,
        "paths": [f"/api/v{i}/endpoint" for i in range(18)],
    },
    
    # Sensitive path abuse (>5 hits to sensitive paths)
    "192.0.2.200": {
        "type": "sensitive",
        "requests": 10,
        "paths": ["/wp-login.php"] * 10,
    },
    "192.0.2.201": {
        "type": "sensitive",
        "requests": 12,
        "paths": ["/admin"] * 8 + ["/login"] * 4,
    },
    "192.0.2.202": {
        "type": "sensitive",
        "requests": 8,
        "paths": ["/.env"] * 8,
    },
    
    # Multi-pattern attackers (triggers multiple detections)
    "10.10.10.100": {
        "type": "multi",
        "requests": 30,
        "paths": ["/wp-login.php"] * 10 + [f"/scan_{i}" for i in range(20)],
    },
    "10.10.10.101": {
        "type": "multi",
        "requests": 35,
        "paths": ["/admin"] * 8 + ["/.env"] * 3 + [f"/test/{i}" for i in range(24)],
    },
}

# Generate log entries for malicious IPs
entries = []
base_time = datetime.now()
countries = ["US", "GB", "FR", "DE", "SG", "IN"]
hosts = ["api.company.com", "shop.company.com", "portal.company.com", "app.company.com", "dev.company.com"]

print("🔨 Generating malicious IP patterns...")
for ip, pattern in malicious_patterns.items():
    print(f"   - {ip}: {pattern['type']} ({pattern['requests']} requests)")
    
    for idx in range(pattern["requests"]):
        path = pattern["paths"][idx]
        # Randomize timestamp within last hour
        timestamp = int((base_time - timedelta(seconds=random.randint(0, 3600))).timestamp() * 1000000)
        
        entry = {
            "RayID": f"{random.randint(10**15, 10**16-1):016x}",
            "EdgeStartTimestamp": timestamp,
            "ClientIP": ip,
            "ClientRequestMethod": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "ClientRequestURI": path,
            "ClientRequestHost": random.choice(hosts),
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestUserAgent": "Mozilla/5.0",
            "ClientCountry": random.choice(countries),
            "EdgeResponseStatus": random.choice([200, 301, 302, 401, 403, 404, 500]),
            "WAFAction": random.choice(["allow", "log", "block"]),
        }
        entries.append(entry)

# Append to existing logpush_simulation.json
output_file = "logpush_simulation.json"
print(f"\n📝 Appending {len(entries)} malicious log entries to {output_file}...")

with open(output_file, "a") as f:
    for entry in entries:
        f.write(json.dumps(entry) + "\n")

print(f"✅ Successfully added malicious patterns!")
print(f"\n📊 Expected Detections:")
print(f"   - High volume IPs (>20 requests): 3 IPs")
print(f"     → 203.0.113.10, 203.0.113.11, 203.0.113.12")
print(f"   - Scanner IPs (>10 unique paths): 3 IPs")
print(f"     → 198.51.100.50, 198.51.100.51, 198.51.100.52")
print(f"   - Sensitive path abuse (>5 hits): 5 IPs")
print(f"     → 192.0.2.200, 192.0.2.201, 192.0.2.202, 10.10.10.100, 10.10.10.101")
print(f"\n🎯 Total expected detections: ~11 malicious IPs")
print(f"\nℹ️  Now run SOAR module from the dashboard to detect these IPs!")
