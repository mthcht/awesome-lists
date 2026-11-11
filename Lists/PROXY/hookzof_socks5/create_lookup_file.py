import requests
import csv
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
    except (socket.gaierror, UnicodeError):
        return None

def fetch_json(name):
    # Upstream sources can change format (e.g. tg/*.json became a plain-text
    # redirect URL), so a broken source is skipped instead of failing the job.
    try:
        response = requests.get(urls[name], timeout=30)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[!] Skipping {name}: not valid JSON or unreachable ({e})")
        return []
    if not isinstance(data, list):
        print(f"[!] Skipping {name}: unexpected JSON structure")
        return []
    return data

# Fetch and process proxy.txt (SOCKS5 proxies) - this is the main source, fail if it breaks
response = requests.get(urls["proxy.txt"], timeout=30)
response.raise_for_status()
for line in response.text.strip().split("\n"):
    line = line.strip()
    if line.count(":") == 1:
        ip, port = line.split(":")
        proxy_data.append([ip, port, "proxy.txt"])

# Fetch and process mtproto.json (Telegram MTProto proxies)
for entry in fetch_json("mtproto.json"):
    if isinstance(entry, dict) and "host" in entry and "port" in entry:
        ip = resolve_host(entry["host"])
        if ip:
            proxy_data.append([ip, str(entry["port"]), "mtproto.json"])

# Fetch and process socks.json (Telegram SOCKS proxies)
for entry in fetch_json("socks.json"):
    if isinstance(entry, dict) and "ip" in entry and "port" in entry:
        proxy_data.append([entry["ip"], str(entry["port"]), "socks.json"])

if not proxy_data:
    raise SystemExit("[!] No proxies collected, refusing to overwrite the CSV with an empty list")

# Write to CSV file
with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["dest_ip", "dest_port", "metadata_comment"])
    writer.writerows(proxy_data)

print(f"CSV file '{csv_filename}' created successfully with {len(proxy_data)} entries.")
