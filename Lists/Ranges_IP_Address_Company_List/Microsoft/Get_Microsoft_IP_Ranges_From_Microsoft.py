import requests
import json
import logging
import sys
import pandas as pd
from pathlib import Path
from requests_html import HTMLSession
from io import StringIO


def parse_and_download_files(servicetags_public, msftpublic_ips, officeworldwide_ips):
    # URL for Feeds
    azurepublic = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
    msftpublic = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=53602"
    officeworldwide = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"

    session = HTMLSession()
    azure_resp = session.get(azurepublic)
    links = azure_resp.html.links
    json_link = [link for link in links if ".json" in link]

    msft_resp = session.get(msftpublic)
    links = msft_resp.html.links
    csv_link = [link for link in links if ".csv" in link]

    # Download links
    azure_json = requests.get(json_link[0])
    msft_csv = requests.get(csv_link[0])
    o365_json = requests.get(officeworldwide, stream=True)
    logging.info("Writing ServiceTags_Public.json file to output directory")
    with open(servicetags_public, "w") as f:
        json.dump(azure_json.json(), f, indent=4)

    # replace headers for splunk fields
    csv_data = msft_csv.content.decode('utf-8')
    df = pd.read_csv(StringIO(csv_data))
    df.columns = ['dest_ip', 'metadata_comment']
    df.to_csv(msftpublic_ips, index=False)
    
    logging.info("Writing OfficeWorldWide-IPRanges.json file to output directory")
    with open(officeworldwide_ips, "w") as f:
        json.dump(o365_json.json(), f, indent=4)


def json_to_custom_csv_service_tags(json_file, csv_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    records = []
    if isinstance(data, dict) and 'values' in data:
        data = data['values']

    for entry in data:
        if 'properties' in entry and 'addressPrefixes' in entry['properties']:
            for ip_range in entry['properties']['addressPrefixes']:
                record = {'dest_ip': ip_range}
                for key, value in entry['properties'].items():
                    if key != 'addressPrefixes':
                        record[f'metadata_{key}'] = value
                records.append(record)
        else:
            logging.warning(f"'properties.addressPrefixes' not found in entry: {entry}")

    if records:
        df = pd.DataFrame(records)
        df.to_csv(csv_file, index=False)
    else:
        logging.error(f"No records found with 'properties.addressPrefixes' in the data")


def json_to_custom_csv_office_worldwide(json_file, csv_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    records = []
    for entry in data:
        if 'ips' in entry:
            for ip_range in entry['ips']:
                record = {'dest_ip': ip_range}
                for key, value in entry.items():
                    if key != 'ips':
                        record[f'metadata_{key}'] = value
                records.append(record)
        else:
            logging.warning(f"'ips' not found in entry: {entry}")

    if records:
        df = pd.DataFrame(records)
        df.to_csv(csv_file, index=False)
    else:
        logging.error(f"No records found with 'ips' in the data")


def main():
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(asctime)s:%(levelname)s: %(message)s",
    )

    curr_path = Path.cwd()

    servicetags_public = curr_path / "ServiceTags_Public.json"
    msftpublic_ips = curr_path / "MSFT_PublicIPs.csv"
    officeworldwide_ips = curr_path / "OfficeWorldWide-IPRanges.json"

    logging.info(f"Writing json file to output directory: {servicetags_public}")
    logging.info(f"Writing csv file to output directory: {msftpublic_ips}")
    logging.info(f"Writing json file to output directory: {officeworldwide_ips}")
    parse_and_download_files(servicetags_public, msftpublic_ips, officeworldwide_ips)

    # Convert JSON files to CSV files
    logging.info(f"Converting {servicetags_public} to CSV")
    json_to_custom_csv_service_tags(servicetags_public, curr_path / "ServiceTags_Public.csv")

    logging.info(f"Converting {officeworldwide_ips} to CSV")
    json_to_custom_csv_office_worldwide(officeworldwide_ips, curr_path / "OfficeWorldWide-IPRanges.csv")


if __name__ == "__main__":
    main()