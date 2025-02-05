import os
import csv
from collections import defaultdict

# Output CSV file
output_filename = "ALL_PROXY_Lists.csv"

# Dictionary to store unique proxy entries
proxy_dict = defaultdict(set)

# Search for all CSV files starting with "PROXY_ALL_" recursively
csv_files = []
for root, _, files in os.walk("."):
    for file in files:
        if file.startswith("PROXY_ALL_") and file.endswith(".csv"):
            csv_files.append(os.path.join(root, file))

# Read and process each CSV file
for csv_file in csv_files:
    with open(csv_file, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # Skip header
        for row in reader:
            if len(row) < 2:
                continue
            dest_ip, dest_port = row[:2]
            dest_ip = dest_ip.strip()
            dest_port = dest_port.strip()
            if dest_ip == "0.0.0.0" or not dest_ip:
                continue  # Skip entries with IP 0.0.0.0 or empty IPs
            metadata = row[2] if len(row) > 2 else ""
            key = (dest_ip, dest_port)
            proxy_dict[key].add(os.path.basename(csv_file))

# Sort proxies by IP address
sorted_proxies = sorted(proxy_dict.items(), key=lambda x: x[0][0])

# Write to the unified CSV file
with open(output_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["dest_ip", "dest_port", "metadata_comment"])
    for (dest_ip, dest_port), sources in sorted_proxies:
        writer.writerow([dest_ip, dest_port, ", ".join(sorted(sources))])

print(f"CSV file '{output_filename}' created successfully with {len(sorted_proxies)} unique entries.")
