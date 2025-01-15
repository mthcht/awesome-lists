import requests
import zipfile
import os
import re
import csv
import socket
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
URL = "https://surfshark.com/api/v1/server/configurations"
ZIP_PATH = "configurations.zip"
EXTRACT_DIR = "ovpn_files"
CSV_FILE = "surfshark_vpn_servers_domains_and_ips_list.csv"
OVPN_PATTERN = re.compile(r"remote\s+([^\s]+)\s+(\d+)")

def download_zip(url, zip_path):
    try:
        logging.info(f"Downloading {url}...")
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        with open(zip_path, "wb") as file:
            file.write(response.content)
        logging.info(f"Downloaded {zip_path}")
    except requests.RequestException as e:
        logging.error(f"Failed to download file: {e}")
        raise

def extract_zip(zip_path, extract_dir):
    try:
        logging.info(f"Extracting {zip_path} to {extract_dir}...")
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
        logging.info("Extraction complete")
    except zipfile.BadZipFile as e:
        logging.error(f"Invalid zip file: {e}")
        raise

def parse_ovpn_files(folder, pattern):
    logging.info(f"Parsing .ovpn files in {folder}...")
    data = []
    for file in Path(folder).rglob("*.ovpn"):
        with open(file, "r") as f:
            content = f.read()
            match = pattern.search(content)
            if match:
                domain, port = match.groups()
                data.append({"dest_nt_domain": domain, "dest_port": port})
    logging.info(f"Found {len(data)} entries")
    return data

def resolve_domains(data):
    logging.info("Resolving domain names to IPs...")
    for entry in data:
        try:
            entry["dest_ip"] = socket.gethostbyname(entry["dest_nt_domain"])
        except socket.gaierror:
            entry["dest_ip"] = "Resolution Failed"
    logging.info("Domain resolution complete")

def save_to_csv(data, csv_file):
    logging.info(f"Saving data to {csv_file}...")
    with open(csv_file, "w", newline="") as csvfile:
        fieldnames = ["dest_nt_domain", "dest_port", "dest_ip"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    logging.info(f"Data saved to {csv_file}")

def cleanup(files):
    logging.info("Cleaning up temporary files...")
    for file in files:
        try:
            if os.path.isdir(file):
                for root, _, files in os.walk(file, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    os.rmdir(root)
            elif os.path.isfile(file):
                os.remove(file)
        except Exception as e:
            logging.warning(f"Failed to clean up {file}: {e}")

# Main script
if __name__ == "__main__":
    try:
        download_zip(URL, ZIP_PATH)
        extract_zip(ZIP_PATH, EXTRACT_DIR)
        data = parse_ovpn_files(EXTRACT_DIR, OVPN_PATTERN)
        resolve_domains(data)
        save_to_csv(data, CSV_FILE)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        cleanup([ZIP_PATH, EXTRACT_DIR])
