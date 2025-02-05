import requests
import csv

# URL of the proxy list
url = "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxylist.txt"

# Output CSV file
csv_filename = "PROXY_ALL_fresh_proxy_list.csv"

# List to store proxy data
proxy_data = []

# Fetch and process proxylist.txt (IP:Port proxies)
response = requests.get(url)
if response.status_code == 200:
    for line in response.text.strip().split("\n"):
        if ":" in line:
            ip, port = line.strip().split(":")
            proxy_data.append([ip, port, "proxylist.txt"])

# Write to CSV file
with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["dest_ip", "dest_port", "metadata_comment"])
    writer.writerows(proxy_data)

print(f"CSV file '{csv_filename}' created successfully with {len(proxy_data)} entries.")
