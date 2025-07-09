#!/usr/bin/env python3
import os
import json
import csv
import requests

# === CONFIG ===
URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.path.join(SCRIPT_DIR, "aws_ip_ranges.csv")

# === MAIN ===
def update_aws_ip_ranges():
    try:
        response = requests.get(URL, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[ERROR] Failed to fetch AWS IP ranges: {e}")
        return

    prefixes = data.get("prefixes", [])
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["dest_ip", "metadata_region", "metadata_service", "metadata_network_border_group"])
        for entry in prefixes:
            writer.writerow([
                entry.get("ip_prefix", ""),
                entry.get("region", ""),
                entry.get("service", ""),
                entry.get("network_border_group", "")
            ])

    print(f"[+] CSV file updated: {OUTPUT_CSV}")

if __name__ == "__main__":
    update_aws_ip_ranges()
