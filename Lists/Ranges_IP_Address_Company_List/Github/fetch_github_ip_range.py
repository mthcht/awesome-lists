import requests
import csv
import os
import datetime

# Config
url = "https://api.github.com/meta"
csv_filename = "github_ip_ranges.csv"
today = datetime.date.today().isoformat()

# Fields of interest in the metadata
ip_fields = [
    "actions",
    "git",
    "web",
    "api",
    "packages",
    "pages",
    "importer",
    "dependabot",
    "hooks"
]

# Fetch metadata
response = requests.get(url)
response.raise_for_status()
data = response.json()

# Parse new IP entries
new_entries = {}
for field in ip_fields:
    for ip in data.get(field, []):
        new_entries[ip] = f"GitHub {field} IP range"

# Load previous data if exists
existing_data = {}
if os.path.exists(csv_filename):
    with open(csv_filename, mode="r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            existing_data[row["src_ip"]] = row

# Merge and update records
updated_rows = []
all_ips = set(existing_data.keys()).union(new_entries.keys())

for ip in sorted(all_ips):
    comment = new_entries.get(ip, existing_data.get(ip, {}).get("metadata_comment", ""))
    first_seen = existing_data.get(ip, {}).get("first_seen", today)
    last_seen = today if ip in new_entries else existing_data.get(ip, {}).get("last_seen", today)
    active = "yes" if ip in new_entries else "no"

    updated_rows.append({
        "src_ip": ip,
        "metadata_comment": comment,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "active": active
    })

# Write to CSV
with open(csv_filename, mode="w", newline="") as f:
    fieldnames = ["src_ip", "metadata_comment", "first_seen", "last_seen", "active"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(updated_rows)

print(f"Updated IP data saved to: {csv_filename}")
