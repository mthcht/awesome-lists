import requests
import csv
import json

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

# Process proxy.txt (SOCKS5 proxies)
response = requests.get(urls["proxy.txt"])
if response.status_code == 200:
    lines = response.text.strip().split("\n")
    for line in lines:
        if ":" in line:
            ip, port = line.split(":")
            proxy_data.append([ip, port, "proxy.txt"])

# Process mtproto.json (Telegram MTProto proxies)
response = requests.get(urls["mtproto.json"])
if response.status_code == 200:
    mtproto_list = json.loads(response.text)
    for entry in mtproto_list:
        proxy_data.append([entry["host"], entry["port"], "mtproto.json"])

# Process socks.json (Telegram SOCKS proxies)
response = requests.get(urls["socks.json"])
if response.status_code == 200:
    socks_list = json.loads(response.text)
    for entry in socks_list:
        proxy_data.append([entry["ip"], entry["port"], "socks.json"])

# Write to CSV file
with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["dest_ip", "dest_port", "metadata_comment"])
    writer.writerows(proxy_data)

print(f"CSV file '{csv_filename}' created successfully with {len(proxy_data)} entries.")
