import requests
import json
import logging
import sys
import pandas as pd
from pathlib import Path
from requests_html import HTMLSession
from io import StringIO
import re


def parse_and_download_files(servicetags_public, msftpublic_ips, officeworldwide_ips):
    azurepublic = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
    msftpublic = "https://www.microsoft.com/en-us/download/details.aspx?id=53602"
    officeworldwide = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"

    session = HTMLSession()
    azure_resp = session.get(azurepublic)
    json_link = [link for link in azure_resp.html.links if ".json" in link]

    msft_resp = session.get(msftpublic)
    csv_link = [link for link in msft_resp.html.links if ".csv" in link]

    azure_json = requests.get(json_link[0])
    msft_csv = requests.get(csv_link[0])
    o365_json = requests.get(officeworldwide, stream=True)

    logging.info("Writing ServiceTags_Public.json file")
    with open(servicetags_public, "w") as f:
        json.dump(azure_json.json(), f, indent=4)

    csv_data = msft_csv.content.decode('utf-8')
    df = pd.read_csv(StringIO(csv_data))
    df.columns = ['dest_ip', 'metadata_comment']
    df.to_csv(msftpublic_ips, index=False)

    logging.info("Writing OfficeWorldWide-IPRanges.json file")
    with open(officeworldwide_ips, "w") as f:
        json.dump(o365_json.json(), f, indent=4)


def extract_service_tags_to_folders(json_file, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(json_file, 'r') as f:
        data = json.load(f)

    for entry in data.get('values', []):
        tag_id = entry.get('id', 'unknown').replace('/', '_')
        tag_dir = output_dir / tag_id
        tag_dir.mkdir(parents=True, exist_ok=True)

        # Write full service tag
        with open(tag_dir / "serviceTag.json", "w") as f:
            json.dump(entry, f, indent=4)

        # Extract address prefixes
        prefixes = entry.get("properties", {}).get("addressPrefixes", [])
        with open(tag_dir / "ips.json", "w") as f:
            json.dump(prefixes, f, indent=4)

        ipv4 = [ip for ip in prefixes if re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d+$', ip)]
        ipv6 = [ip for ip in prefixes if ":" in ip]

        with open(tag_dir / "ipv4.json", "w") as f:
            json.dump(ipv4, f, indent=4)
        with open(tag_dir / "ipv6.json", "w") as f:
            json.dump(ipv6, f, indent=4)

        # Save CSV with tag name
        csv_name = f"{tag_id}_ips.csv"
        df_ips = pd.DataFrame(prefixes, columns=["dest_ip"])
        df_ips.to_csv(tag_dir / csv_name, index=False)


def json_to_custom_csv_service_tags(json_file, csv_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    records = []
    for entry in data.get('values', []):
        for ip_range in entry.get('properties', {}).get('addressPrefixes', []):
            record = {'dest_ip': ip_range}
            for k, v in entry.get('properties', {}).items():
                if k != 'addressPrefixes':
                    record[f'metadata_{k}'] = v
            records.append(record)

    pd.DataFrame(records).to_csv(csv_file, index=False)


def json_to_custom_csv_office_worldwide(json_file, csv_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    records = []
    for entry in data:
        for ip in entry.get("ips", []):
            record = {'dest_ip': ip}
            for k, v in entry.items():
                if k != 'ips':
                    record[f'metadata_{k}'] = v
            records.append(record)

    pd.DataFrame(records).to_csv(csv_file, index=False)


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s:%(levelname)s: %(message)s")

    curr_path = Path.cwd()
    servicetags_public = curr_path / "ServiceTags_Public.json"
    msftpublic_ips = curr_path / "MSFT_PublicIPs.csv"
    officeworldwide_ips = curr_path / "OfficeWorldWide-IPRanges.json"

    parse_and_download_files(servicetags_public, msftpublic_ips, officeworldwide_ips)

    json_to_custom_csv_service_tags(servicetags_public, curr_path / "ServiceTags_Public.csv")
    json_to_custom_csv_office_worldwide(officeworldwide_ips, curr_path / "OfficeWorldWide-IPRanges.csv")

    extract_service_tags_to_folders(servicetags_public, curr_path / "serviceTags")


if __name__ == "__main__":
    main()
