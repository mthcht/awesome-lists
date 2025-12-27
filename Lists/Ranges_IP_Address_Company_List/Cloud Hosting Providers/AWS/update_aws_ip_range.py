#!/usr/bin/env python3
import os
import csv
import requests
from datetime import datetime

# === CONFIG ===
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_MASTER_CSV = os.path.join(OUTPUT_DIR, "aws_ip_ranges.csv")
URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

# === FETCH JSON DATA ===
resp = requests.get(URL, timeout=30)
data = resp.json()

# === PROCESS PREFIXES ===
prefixes = data.get("prefixes", [])
service_map = {}

with open(OUTPUT_MASTER_CSV, "w", newline="") as master_file:
    writer = csv.writer(master_file)
    writer.writerow(["dest_ip", "metadata_region", "metadata_service", "metadata_network_border_group"])

    for entry in prefixes:
        ip = entry["ip_prefix"]
        region = entry["region"]
        service = entry["service"]
        nbg = entry["network_border_group"]

        writer.writerow([ip, region, service, nbg])

        if service not in service_map:
            service_map[service] = []
        service_map[service].append([ip, region, service, nbg])

# === WRITE PER-SERVICE CSVs ===
for service, rows in service_map.items():
    safe_name = service.lower().replace(" ", "_")
    path = os.path.join(OUTPUT_DIR, f"aws_ip_ranges_{safe_name}.csv")
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["dest_ip", "metadata_region", "metadata_service", "metadata_network_border_group"])
        writer.writerows(rows)
