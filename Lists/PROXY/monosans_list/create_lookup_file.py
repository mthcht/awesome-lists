import csv
import re

# Define input and output files
input_file = "all.txt"
output_file = "PROXY_ALL_monosans_List.csv"

# Regular expression to match the proxy type, IP, and port
pattern = re.compile(r"(http|https|socks4|socks5)://([\d\.]+):(\d+)")

# Read the input file and extract the required fields
data = []
with open(input_file, "r") as f:
    for line in f:
        match = pattern.match(line.strip())
        if match:
            proxy_type, ip, port = match.groups()
            data.append([ip, port, proxy_type])

# Write to CSV file
with open(output_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["dest_ip", "dest_port", "meta.comment"])  # Write header
    writer.writerows(data)

print(f"Lookup file '{output_file}' created successfully.")
