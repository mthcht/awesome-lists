import requests
import csv

# URLs for IP ranges
urls = {
    "https://www.cloudflare.com/ips-v4": [],
    "https://www.cloudflare.com/ips-v6": []
}

# Fetch IPs
for url in urls:
    response = requests.get(url)
    response.raise_for_status()
    urls[url] = response.text.strip().splitlines()

# Write to CSV
with open("cloudflare_ips.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["dest_ip", "metadata_comment"])
    for url, ip_list in urls.items():
        for ip in ip_list:
            writer.writerow([ip, f"From {url}"])
