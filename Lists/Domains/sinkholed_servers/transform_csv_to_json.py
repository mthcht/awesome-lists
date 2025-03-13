import requests
import csv
import json
import argparse
import os
from tldextract import extract

def load_csv_from_url(csv_url):
    """Download and parse CSV from a given URL."""
    print(f"[INFO] Downloading CSV from {csv_url}...")
    try:
        response = requests.get(csv_url)
        response.raise_for_status()
        lines = response.content.decode('utf-8').splitlines()
        return csv.DictReader(lines)
    except requests.RequestException as e:
        print(f"[ERROR] Failed to fetch CSV from URL: {e}")
        exit(1)

def load_csv_from_file(csv_path):
    """Load CSV data from a local file."""
    if not os.path.exists(csv_path):
        print(f"[ERROR] Local CSV file not found: {csv_path}")
        exit(1)

    print(f"[INFO] Loading CSV from local file: {csv_path}")
    try:
        with open(csv_path, mode='r', encoding='utf-8') as file:
            return csv.DictReader(file)
    except Exception as e:
        print(f"[ERROR] Failed to read local CSV file: {e}")
        exit(1)

def process_csv_data(reader):
    """Process CSV data to generate JSON output."""
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

    return {"ns_servers": ns_servers, "domains": domains}

def main():
    parser = argparse.ArgumentParser(description="Convert Sinkholed Domains CSV to JSON.")
    parser.add_argument("--csv-url", help="URL of the CSV file", default="https://github.com/mthcht/awesome-lists/raw/refs/heads/main/Lists/Domains/sinkholed_servers/sinkholed_domains.csv")
    parser.add_argument("--csv-file", help="Path to a local CSV file (optional)")
    parser.add_argument("--output", help="Output JSON file", default="sinkholed_domains.json")
    
    args = parser.parse_args()

    if args.csv_file:
        reader = load_csv_from_file(args.csv_file)
    else:
        reader = load_csv_from_url(args.csv_url)

    final_data = process_csv_data(reader)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(final_data, f, indent=2)

    print(f"[SUCCESS] JSON saved to {args.output}")
    print(f"Domains processed: {len(final_data['domains'])}; Unique NS servers: {len(final_data['ns_servers'])}")

if __name__ == "__main__":
    main()
