#!/usr/bin/env python3
"""Test if SOAR can parse the logpush file and detect IPs."""

import json
from pathlib import Path
from collections import defaultdict, Counter

# Parse the logpush file
logpush_file = Path("logpush_simulation.json")
print(f"Reading {logpush_file}...")

ip_requests = defaultdict(list)
ip_paths = defaultdict(set)
sensitive_paths = {"/wp-login.php", "/admin", "/login", "/.env"}

entries_parsed = 0
with open(logpush_file) as f:
    for line in f:
        entries_parsed += 1
        try:
            entry = json.loads(line.strip())
            client_ip = entry.get("ClientIP")
            request_uri = entry.get("ClientRequestURI", "")
            
            if client_ip:
                ip_requests[client_ip].append(request_uri)
                ip_paths[client_ip].add(request_uri)
        except json.JSONDecodeError:
            continue

print(f"✅ Parsed {entries_parsed} entries")
print(f"✅ Found {len(ip_requests)} unique IPs")

# Apply detection rules
high_volume_ips = []
scanner_ips = []
sensitive_abuse_ips = []

REQUEST_THRESHOLD = 20
UNIQUE_PATH_THRESHOLD = 10
SENSITIVE_PATH_THRESHOLD = 5

for ip, requests in ip_requests.items():
    request_count = len(requests)
    unique_paths = len(ip_paths[ip])
    sensitive_hits = sum(1 for path in requests if any(s in path for s in sensitive_paths))
    
    if request_count > REQUEST_THRESHOLD:
        high_volume_ips.append((ip, request_count, unique_paths, sensitive_hits))
    
    if unique_paths > UNIQUE_PATH_THRESHOLD:
        scanner_ips.append((ip, request_count, unique_paths, sensitive_hits))
    
    if sensitive_hits > SENSITIVE_PATH_THRESHOLD:
        sensitive_abuse_ips.append((ip, request_count, unique_paths, sensitive_hits))

print(f"\n🚨 Detection Results:")
print(f"   - High volume (>{REQUEST_THRESHOLD} requests): {len(high_volume_ips)} IPs")
print(f"   - Scanners (>{UNIQUE_PATH_THRESHOLD} unique paths): {len(scanner_ips)} IPs")
print(f"   - Sensitive path abuse (>{SENSITIVE_PATH_THRESHOLD} hits): {len(sensitive_abuse_ips)} IPs")

# Combine all detections
all_detections = set()
for ip, _, _, _ in high_volume_ips + scanner_ips + sensitive_abuse_ips:
    all_detections.add(ip)

print(f"\n📊 Total malicious IPs detected: {len(all_detections)}")

# Show samples
if high_volume_ips:
    print(f"\nSample high volume IPs:")
    for ip, req_count, paths, sens in high_volume_ips[:3]:
        print(f"   - {ip}: {req_count} requests, {paths} unique paths, {sens} sensitive hits")

if scanner_ips:
    print(f"\nSample scanner IPs:")
    for ip, req_count, paths, sens in scanner_ips[:3]:
        print(f"   - {ip}: {req_count} requests, {paths} unique paths, {sens} sensitive hits")
