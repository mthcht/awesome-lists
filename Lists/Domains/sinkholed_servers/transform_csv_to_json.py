import requests
import csv
import json
from tldextract import extract

CSV_URL = "https://github.com/mthcht/awesome-lists/raw/refs/heads/main/Lists/Domains/sinkholed_servers/sinkholed_domains.csv"

response = requests.get(CSV_URL)
response.raise_for_status()

lines = response.content.decode('utf-8').splitlines()
reader = csv.DictReader(lines)

ns_servers = {}
ns_servers_rev = {}  # For reverse lookup
domains = []

ns_id_counter = 1

for row in reader:
    domain = row['dest_nt_domain'].strip()
    ns_server = row['metadata_NS_server'].strip()
    tld = extract(domain).suffix

    if ns_server not in ns_servers_rev:
        ns_servers[str(ns_id_counter)] = ns_server
        ns_servers_rev[ns_server] = ns_id_counter
        ns_id_counter += 1

    domains.append({
        "domain": domain,
        "tld": tld,
        "ns_id": ns_servers_rev[ns_server]
    })

final_data = {
    "ns_servers": ns_servers,
    "domains": domains
}

with open('sinkholed_domains.json', 'w') as f:
    json.dump(final_data, f, indent=2)

print(f"Domains processed: {len(domains)}; Unique NS servers: {len(ns_servers)}")
