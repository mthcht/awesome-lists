import csv
import logging
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")

# URL to download the CSV
CSV_URL = "https://certcentral.org/api/download_csv"
LOCAL_PATH = "certcentral_signers_list.csv"

# Mapping of original headers to CIM-compliant names
CIM_HEADER_MAPPING = {
    "Hash": "file_hash",
    "Malware": "malware_label",
    "Signer": "signer",
    "Issuer Short": "issuer_short",
    "Issuer": "issuer_org",
    "Serial": "certificate_serial",
    "Thumbprint": "certificate_thumbprint",
    "Valid From": "valid_from",
    "Valid To": "valid_to",
    "Country": "certificate_country",
    "State": "certificate_state",
    "Locality": "certificate_locality",
    "Email": "certificate_email"
}

def download_csv(url):
    logging.debug(f"Downloading CSV from: {url}")
    response = requests.get(url, verify=False)
    response.raise_for_status()
    logging.debug("CSV download complete")
    return response.content.decode("utf-8")

def convert_headers_to_cim(csv_data):
    reader = csv.DictReader(csv_data.splitlines())
    logging.debug("Original headers: %s", reader.fieldnames)

    # Create new headers using the CIM mapping
    new_headers = [CIM_HEADER_MAPPING.get(h, h.lower().replace(" ", "_")) for h in reader.fieldnames]
    logging.debug("Mapped CIM headers: %s", new_headers)

    rows = list(reader)
    logging.debug(f"Number of rows: {len(rows)}")
    return new_headers, rows

def write_csv(headers, rows, path):
    logging.debug(f"Writing processed CSV to: {path}")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            converted = {CIM_HEADER_MAPPING.get(k, k.lower().replace(" ", "_")): v for k, v in row.items()}
            writer.writerow(converted)
    logging.debug("CSV write complete")

def main():
    csv_raw = download_csv(CSV_URL)
    headers, rows = convert_headers_to_cim(csv_raw)
    write_csv(headers, rows, LOCAL_PATH)

main()  
