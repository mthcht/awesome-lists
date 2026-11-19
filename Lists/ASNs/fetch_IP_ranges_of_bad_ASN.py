
import csv
import subprocess
import os
import sys
import json
import requests

# Input CSV files
latest_csv_file_path = 'latest_bad_asn_phishing_list.csv'
static_csv_file_path = 'bad_asn_static_list.csv'
spamhaus_csv_file_path = 'spamhaus_asn_list.csv'

# ASN retrieval script
script_path = os.path.join(
    '..', 'Ranges_IP_Address_Company_List',
    'bgp.he.net', 'get_ip_range.py'
)

spamhaus_url = 'https://www.spamhaus.org/drop/asndrop.json'


def read_as_numbers(csv_file_path, column_name='as_number'):
    as_numbers = []

    with open(csv_file_path, encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            asn = row[column_name].strip().upper().removeprefix('AS')
            if asn.isdigit():
                as_numbers.append(f'AS{asn}')

    return as_numbers


def fetch_spamhaus_asn_data():
    response = requests.get(spamhaus_url, timeout=60)
    response.raise_for_status()

    spamhaus_data = []

    for line in response.text.splitlines():
        try:
            entry = json.loads(line)
            if 'asn' in entry:
                spamhaus_data.append(entry)
        except json.JSONDecodeError:
            print(f"Skipping invalid JSON line: {line[:100]}")

    with open(
        spamhaus_csv_file_path, 'w',
        encoding='utf-8', newline=''
    ) as file:
        writer = csv.writer(file)
        writer.writerow(['as_number', 'rir', 'domain', 'cc', 'asname'])

        for entry in spamhaus_data:
            writer.writerow([
                entry.get('asn', ''),
                entry.get('rir', ''),
                entry.get('domain', ''),
                entry.get('cc', ''),
                entry.get('asname', '')
            ])

    return [
        f"AS{str(entry['asn']).upper().removeprefix('AS')}"
        for entry in spamhaus_data
    ]


# Collect and deduplicate ASNs
spamhaus_as_numbers = fetch_spamhaus_asn_data()
latest_as_numbers = read_as_numbers(latest_csv_file_path)
static_as_numbers = read_as_numbers(static_csv_file_path)

combined_as_numbers = sorted(set(
    latest_as_numbers + static_as_numbers + spamhaus_as_numbers
))

if not combined_as_numbers:
    raise RuntimeError("No ASNs found. Refusing to overwrite existing data.")

as_numbers_str = ','.join(combined_as_numbers)
print(f"Fetching IP ranges for {len(combined_as_numbers)} unique ASNs")

# Remove stale completion marker
sentinel_file = 'ASN_FETCH_DONE.log'

if os.path.exists(sentinel_file):
    os.remove(sentinel_file)

# Execute the retrieval script exactly once
subprocess.run(
    [sys.executable, script_path, '-list', as_numbers_str, '-format', 'csv'],
    check=True
)

# Confirm successful completion
if not os.path.isfile(sentinel_file):
    raise RuntimeError("ASN retrieval did not create its completion marker")

# Collect generated files before replacing previous data
generated_files = [
    file for file in os.listdir('.')
    if file.startswith('AS') and file.endswith('_IP_Ranges.csv')
]

if not generated_files:
    raise RuntimeError("No ASN IP range CSVs generated. Existing data preserved.")

output_folder = 'ASN_IP_Ranges'
os.makedirs(output_folder, exist_ok=True)

# Remove previous generated CSVs
for file in os.listdir(output_folder):
    file_path = os.path.join(output_folder, file)
    if os.path.isfile(file_path) and file.endswith('_IP_Ranges.csv'):
        os.remove(file_path)

# Move updated CSVs into output directory
for file in generated_files:
    os.replace(file, os.path.join(output_folder, file))

os.remove(sentinel_file)

print(f"Updated {len(generated_files)} ASN IP range CSV files")
