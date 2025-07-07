import csv
import subprocess
import os
import json
import requests

# Paths to the CSV files
latest_csv_file_path = 'latest_bad_asn_phishing_list.csv'
static_csv_file_path = 'bad_asn_static_list.csv'
spamhaus_csv_file_path = 'spamhaus_asn_list.csv'
evild3ad_csv_file_path = 'evild3ad-ASN-BlackList.csv'

# Path to the script to be executed using relative path
script_path = os.path.join('..', 'Ranges_IP_Address_Company_List', 'bgp.he.net', 'get_ip_range.py')

# URLs for fetching data
spamhaus_url = 'https://www.spamhaus.org/drop/asndrop.json'
evild3ad_url = 'https://raw.githubusercontent.com/evild3ad/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/ASN-Blacklist.csv'

# Function to read AS numbers from a CSV file
def read_as_numbers(csv_file_path, column_name='as_number'):
    as_numbers = []
    with open(csv_file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            as_numbers.append('AS' + row[column_name].strip())
    return as_numbers

# Function to fetch and save Spamhaus ASN data
def fetch_spamhaus_asn_data():
    response = requests.get(spamhaus_url)
    response.raise_for_status()
    
    spamhaus_data = []
    for line in response.text.splitlines():
        try:
            entry = json.loads(line)
            if 'asn' in entry:
                spamhaus_data.append(entry)
        except json.JSONDecodeError:
            print(f"Failed to decode line: {line}")

    # Save Spamhaus data to a CSV file
    with open(spamhaus_csv_file_path, mode='w', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['as_number', 'rir', 'domain', 'cc', 'asname'])
        for entry in spamhaus_data:
            writer.writerow([entry['asn'], entry['rir'], entry['domain'], entry['cc'], entry['asname']])

    return ['AS' + str(entry['asn']) for entry in spamhaus_data]

# Function to fetch and save the evild3ad ASN blacklist
def fetch_evild3ad_asn_data():
    response = requests.get(evild3ad_url)
    response.raise_for_status()
    
    with open(evild3ad_csv_file_path, mode='w', encoding='utf-8') as file:
        file.write(response.text)
    
    return read_as_numbers(evild3ad_csv_file_path, column_name='ASN')

# Fetch Spamhaus AS numbers
spamhaus_drop_as_numbers = fetch_spamhaus_asn_data()

# Fetch evild3ad ASN blacklist
evild3ad_as_numbers = fetch_evild3ad_asn_data()

# Read AS numbers from other CSV files
latest_as_numbers = read_as_numbers(latest_csv_file_path)
static_as_numbers = read_as_numbers(static_csv_file_path)

# Combine AS numbers from all sources
combined_as_numbers = list(set(latest_as_numbers + static_as_numbers + spamhaus_drop_as_numbers + evild3ad_as_numbers))

# Join the AS numbers into a single string separated by commas
as_numbers_str = ','.join(combined_as_numbers)

# Construct the command
command = f'python {script_path} -list {as_numbers_str} -format csv'

# Execute the command
subprocess.run(command, shell=True)

print(f"Command executed: {command}")

# Move all output CSVs into subfolder
output_folder = 'ASN_IP_Ranges'
os.makedirs(output_folder, exist_ok=True)

for file in os.listdir('.'):
    if file.startswith('AS') and file.endswith('_IP_Ranges.csv'):
        os.rename(file, os.path.join(output_folder, file))

print(f"Command executed: {command}")
print(f"Moved output CSVs to {output_folder}/")