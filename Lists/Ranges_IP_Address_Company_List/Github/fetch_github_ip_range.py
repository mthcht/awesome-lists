import requests
import csv
import os
import datetime
from collections import defaultdict

# GitHub metadata endpoint
url = "https://api.github.com/meta"
csv_filename = "github_ip_ranges.csv"
today = datetime.date.today().isoformat()

# Metadata fields that contain IPs
ip_fields = [
    "actions", "git", "web", "api", "packages",
    "pages", "importer", "dependabot", "hooks"
]

# Download and parse metadata
response = requests.get(url)
response.raise_for_status()
data = response.json()

# Group IPs and track their categories
new_entries = defaultdict(set)
for field in ip_fields:
    for ip in data.get(field, []):
        new_entries[ip].add(field)

# Load previous CSV data if exists
existing_data = {}
if os.path.exists(csv_filename):
    with open(csv_filename, mode="r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            existing_data[row["src_ip"]] = row

# Merge old and new entries
updated_rows = []
all_ips = set(existing_data) | set(new_entries)

for ip in sorted(all_ips):
    categories = sorted(new_entries[ip]) if ip in new_entries else []
    metadata_comment = (
        f"GitHub {' - '.join(categories)} IP range" if categories else
        existing_data[ip].get("metadata_comment", "")
    )
    first_seen = existing_data[ip]["first_seen"] if ip in existing_data else today
    last_seen = today if ip in new_entries else existing_data[ip]["last_seen"]
    active = "yes" if ip in new_entries else "no"

    updated_rows.append({
        "src_ip": ip,
        "metadata_comment": metadata_comment,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "active": active
    })

# Save CSV
with open(csv_filename, mode="w", newline="") as f:
    fieldnames = ["src_ip", "metadata_comment", "first_seen", "last_seen", "active"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(updated_rows)

print(f"Updated and saved to {csv_filename}")
