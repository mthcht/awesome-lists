import requests
import csv
import json
import socket

# URLs of the proxy lists
urls = {
    "proxy.txt": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "mtproto.json": "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
    "socks.json": "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/socks.json"
}

# Output CSV file
csv_filename = "PROXY_ALL_hookzof_list.csv"

# List to store proxy data
proxy_data = []

# Function to resolve hostnames to IP addresses
def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

# Fetch and process proxy.txt (SOCKS5 proxies)
response = requests.get(urls["proxy.txt"])
if response.status_code == 200:
    for line in response.text.strip().split("\n"):
        if ":" in line:
            ip, port = line.strip().split(":")
            proxy_data.append([ip, port, "proxy.txt"])

# Fetch and process mtproto.json (Telegram MTProto proxies)
response = requests.get(urls["mtproto.json"])
if response.status_code == 200:
    for entry in json.loads(response.text):
        ip = resolve_host(entry["host"])
        if ip:
            proxy_data.append([ip, str(entry["port"]), "mtproto.json"])

# Fetch and process socks.json (Telegram SOCKS proxies)
response = requests.get(urls["socks.json"])
if response.status_code == 200:
    for entry in json.loads(response.text):
        proxy_data.append([entry["ip"], str(entry["port"]), "socks.json"])

# Write to CSV file
with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["dest_ip", "dest_port", "metadata_comment"])
    writer.writerows(proxy_data)

print(f"CSV file '{csv_filename}' created successfully with {len(proxy_data)} entries.")
