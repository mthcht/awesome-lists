import os
import csv
import argparse
import pandas as pd

def load_ns_servers(ns_file):
    """Load the list of sinkhole NS servers from a CSV file."""
    df = pd.read_csv(ns_file)
    return set(df['ns_servers'].dropna().tolist())  # Use a set for faster lookups

def process_zone_file(zone_file, ns_servers, writer):
    """Stream process a zone file and write matching NS records to CSV."""
    with open(zone_file, 'r') as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) >= 5 and parts[3].upper() == "NS":
                domain = parts[0].rstrip(".")
                ns_record = parts[4].rstrip(".")
                if ns_record in ns_servers:
                    writer.writerow([domain, ns_record])

def search_ns_in_zone_files(directory, ns_servers, output_file):
    """Search for domains pointing to known sinkhole NS servers in zone files."""
    print(f"[INFO] Searching for {len(ns_servers)} sinkhole NS servers in {directory}...")

    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["dest_nt_domain", "metadata_NS_server"])

        for root, _, files in os.walk(directory):
            for file in files:
                zone_file_path = os.path.join(root, file)
                print(f"[INFO] Processing {zone_file_path}")
                process_zone_file(zone_file_path, ns_servers, writer)

def main():
    parser = argparse.ArgumentParser(
        description="Extract domains pointing to known sinkhole NS servers from zone files."
    )
    parser.add_argument("directory", help="Path to the directory containing zone files")
    parser.add_argument("ns_file", help="Path to the CSV file containing sinkhole NS servers")
    args = parser.parse_args()

    ns_servers = load_ns_servers(args.ns_file)
    output_file = "sinkholed_domains.csv"
    search_ns_in_zone_files(args.directory, ns_servers, output_file)
    print("[SUCCESS] Results saved to sinkhole_domains.csv")

if __name__ == "__main__":
    main()
