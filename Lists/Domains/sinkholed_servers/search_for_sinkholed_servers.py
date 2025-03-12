import os
import csv
import gzip
import argparse
import pandas as pd

def load_ns_servers(ns_file):
    """Load the list of sinkhole NS servers from a CSV file."""
    df = pd.read_csv(ns_file)
    return set(df['ns_servers'].dropna().tolist())  # Use a set for faster lookups

def process_zone_file(zone_file, ns_servers, writer):
    """Stream process a compressed zone file (.gz) and write matching NS records to CSV."""
    print(f"[INFO] Processing {zone_file}")

    try:
        with gzip.open(zone_file, 'rt', encoding='utf-8', errors='ignore') as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) >= 5 and parts[3].upper() == "NS":
                    domain = parts[0].rstrip(".")
                    ns_record = parts[4].rstrip(".")
                    if ns_record in ns_servers:
                        writer.writerow([domain, ns_record])
    except Exception as e:
        print(f"[ERROR] Failed to process {zone_file}: {e}")

    # Delete the file after processing to save space
    try:
        os.remove(zone_file)
        print(f"[INFO] Deleted {zone_file} to free up space.")
    except Exception as e:
        print(f"[ERROR] Could not delete {zone_file}: {e}")

def search_ns_in_zone_files(directory, ns_servers, output_file):
    """Search for domains pointing to known sinkhole NS servers in compressed zone files."""
    print(f"[INFO] Searching for {len(ns_servers)} sinkhole NS servers in {directory}...")

    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["dest_nt_domain", "metadata_NS_server"])

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".gz"):  # Only process .gz files
                    zone_file_path = os.path.join(root, file)
                    process_zone_file(zone_file_path, ns_servers, writer)

def main():
    parser = argparse.ArgumentParser(
        description="Extract domains pointing to known sinkhole NS servers from compressed zone files."
    )
    parser.add_argument("directory", help="Path to the directory containing compressed zone files (.gz)")
    parser.add_argument("ns_file", help="Path to the CSV file containing sinkhole NS servers")
    args = parser.parse_args()

    ns_servers = load_ns_servers(args.ns_file)
    output_file = "sinkholed_domains.csv"
    search_ns_in_zone_files(args.directory, ns_servers, output_file)
    print("[SUCCESS] Results saved to sinkholed_domains.csv")

if __name__ == "__main__":
    main()
