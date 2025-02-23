import os
import argparse
import pandas as pd
import subprocess

def load_ns_servers(ns_file):
    """Load the list of sinkhole NS servers from a CSV file."""
    df = pd.read_csv(ns_file)
    return df['ns_servers'].dropna().tolist()

def search_ns_in_zone_files(directory, ns_servers):
    """Use grep to quickly find domains with matching NS records in zone files."""
    results = []
    total_ns = len(ns_servers)
    print(f"[INFO] Searching for {total_ns} sinkhole NS servers in {directory} using grep...")

    for idx, ns in enumerate(ns_servers, start=1):
        try:
            print(f"[INFO] ({idx}/{total_ns}) Searching for: {ns}")
            grep_cmd = ["grep", "-rnw", directory, "-e", ns]
            output = subprocess.run(grep_cmd, capture_output=True, text=True, check=False)

            if output.stdout:
                for line in output.stdout.strip().split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        file_path = parts[0]
                        matched_line = ":".join(parts[1:])
                        results.append((matched_line.strip(), ns, file_path))
        except Exception as e:
            print(f"[ERROR] Failed to search for {ns}: {e}")

    return results

def main():
    parser = argparse.ArgumentParser(description="Extract domains pointing to known sinkhole NS servers using grep.")
    parser.add_argument("directory", help="Path to the directory containing zone files")
    parser.add_argument("ns_file", help="Path to the CSV file containing sinkhole NS servers")
    args = parser.parse_args()

    ns_servers = load_ns_servers(args.ns_file)
    results = search_ns_in_zone_files(args.directory, ns_servers)

    if results:
        df = pd.DataFrame(results, columns=["Matched Line", "Sinkhole_NS", "File"])
        df.to_csv("sinkhole_domains.csv", index=False)
        print("[SUCCESS] Results saved to sinkhole_domains.csv")
    else:
        print("[INFO] No matching domains found.")

if __name__ == "__main__":
    main()
