#!/usr/bin/env python3
import requests
import csv

URL = "https://mask-api.icloud.com/egress-ip-ranges.csv"
OUTPUT_FILE = "icloud_relay_ranges.csv"

# Download the file
response = requests.get(URL, timeout=30)
response.raise_for_status()

# Decode lines
lines = response.text.strip().splitlines()

# Add header
header = ["src_ip", "country", "country_lg", "city", "_"]

# Write out as CSV with header
with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(header)
    for line in lines:
        row = line.split(",")
        writer.writerow(row)

print(f"Saved {len(lines)} rows to {OUTPUT_FILE}")
