import csv
import subprocess
import os
import json
import requests

# Paths to the CSV files
latest_csv_file_path = 'latest_bad_asn_phishing_list.csv'
static_csv_file_path = 'bad_asn_static_list.csv'
spamhaus_csv_file_path = 'spamhaus_asn_list.csv'

# Path to the script to be executed using relative path
script_path = os.path.join('..', 'Ranges_IP_Address_Company_List', 'bgp.he.net', 'get_ip_range.py')

# URL to fetch ASN data from Spamhaus
spamhaus_url = 'https://www.spamhaus.org/drop/asndrop.json'

# Function to read AS numbers from a CSV file
def read_as_numbers(csv_file_path):
    as_numbers = []
    with open(csv_file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            as_numbers.append('AS' + row['as_number'])
    return as_numbers

# Function to fetch and save Spamhaus ASN data
def fetch_spamhaus_asn_data():
    response = requests.get(spamhaus_url)
    response.raise_for_status()
    
    spamhaus_data = []
    for line in response.text.splitlines():
        try:
            entry = json.loads(line)
            if 'asn' in entry and 'rir' in entry and 'domain' in entry and 'cc' in entry and 'asname' in entry:
                spamhaus_data.append(entry)
            else:
                print(f"Skipping incomplete entry: {entry}")
        except json.JSONDecodeError:
            print(f"Failed to decode line: {line}")

    # Write Spamhaus data to a CSV file
    with open(spamhaus_csv_file_path, mode='w', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['as_number', 'rir', 'domain', 'cc', 'asname'])
        for entry in spamhaus_data:
            writer.writerow([entry['asn'], entry['rir'], entry['domain'], entry['cc'], entry['asname']])

    # Extract AS numbers
    return ['AS' + str(entry['asn']) for entry in spamhaus_data]

# Fetch Spamhaus AS numbers
spamhaus_drop_as_numbers = fetch_spamhaus_asn_data()

# Read AS numbers from both files
latest_as_numbers = read_as_numbers(latest_csv_file_path)
static_as_numbers = read_as_numbers(static_csv_file_path)

# Combine AS numbers from all sources
combined_as_numbers = list(set(latest_as_numbers + static_as_numbers + spamhaus_drop_as_numbers))

# Join the AS numbers into a single string separated by commas
as_numbers_str = ','.join(combined_as_numbers)

# Construct the command
command = f'python {script_path} -list {as_numbers_str} -format csv'

# Execute the command
subprocess.run(command, shell=True)

print(f"Command executed: {command}")
